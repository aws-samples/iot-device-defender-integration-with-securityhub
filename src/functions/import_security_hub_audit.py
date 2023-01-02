# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import os
import json
import logging
import boto3
import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

securityhub = boto3.client('securityhub')
iot = boto3.client('iot')

RECORDSTATE_ARCHIVED = "ARCHIVED"
RECORDSTATE_ACTIVE = "ACTIVE"
TYPE_PREFIX = "Software and Configuration Checks/AWS IoT Device Defender"


def get_partition(region):
    session = boto3.Session()
    return session.get_partition_for_region(region)


def get_sh_resource_type(iot_finding):
    """Return ASFF Resource type based on IoT Device Defender finding"""
    return "AwsIamRole" if iot_finding['nonCompliantResource']['resourceType'] == "IAM_ROLE" else "Other"


def get_resource_identifier(iot_finding):
    """Get resource name from IoT device Defender finding"""
    resource = iot_finding['nonCompliantResource']['resourceIdentifier']
    if list(resource.keys())[0] == "policyVersionIdentifier":
        return resource["policyVersionIdentifier"]["policyName"]
    else:
        return list(resource.values())[0]


def map_iot_dd_audit_to_security_hub(finding):
    """Create a Security Hub finding based on IoT Device Defender finding"""
    severity = finding['severity']
    resource_id = get_resource_identifier(finding)
    resource_type = get_sh_resource_type(finding)
    account_id = finding['accountId']
    region = finding['region']
    partition = finding['partition']
    check_name = finding['checkName']
    finding_id = f"arn:{partition}:iot-device-defender:{region}:{account_id}:audits/finding/{check_name}-{resource_id}"
    task_id = finding['taskId']
    audit_arn = finding['auditARN']
    record_state = RECORDSTATE_ACTIVE
    status = "FAILED"
    description = finding['reasonForNonCompliance']
    title = "IoT Device Defender: resource {} non compliant to {}".format(
        resource_id, check_name)
    d = datetime.datetime.utcnow()
    new_recorded_time = d.isoformat() + "Z"

    remediation_url = "https://console.aws.amazon.com/iot/home?region=" + \
        region+"#/dd/audit/"+task_id+"/"+check_name
    new_finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": f"arn:{partition}:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": audit_arn,
        "AwsAccountId": account_id,
        "Compliance": {"Status": status},
        "Types": [
            f"{TYPE_PREFIX}/{check_name}"
        ],
        "CreatedAt": new_recorded_time,
        "UpdatedAt": new_recorded_time,
        "Severity": {
            "Label": severity
        },
        "Title": title,
        "Description": description,
        'Remediation': {
            'Recommendation': {
                'Text': 'For directions on how to fix this issue, start mitigation action in AWS IoT Device Defender console',
                'Url': remediation_url
            }
        },
        "ProductFields": {
            "ProviderName": "IoTDeviceDefender",
            "ProviderVersion": "1.0",
        },
        'Resources': [
            {
                'Id': resource_id,
                'Type': resource_type,
                'Partition': "aws",
                'Region': region
            }
        ],
        'Workflow': {'Status': 'NEW'},
        'RecordState': record_state
    }
    return new_finding


def import_new_findings(new_findings):
    """Import new audit findings to Security Hub"""
    try:
        for i in range(0, len(new_findings), 100):
            response = securityhub.batch_import_findings(
                Findings=new_findings[i: i + 100])
            if response['FailedCount'] > 0:
                logger.warning("Failed to import {} findings".format(
                    response['FailedCount']))
            else:
                logger.info("Findings imported to Security Hub")
    except Exception as error:
        logger.error("Error:  %s", error)
        raise


def archive_resolved_findings(new_findings):
    """Archive Security hub findings that were resolved"""
    new_recorded_time = datetime.datetime.utcnow().isoformat() + "Z"
    archived = []
    new_ids = [finding['Id'] for finding in new_findings]

    paginator = securityhub.get_paginator('get_findings')
    findings_for_check_pages = paginator.paginate(Filters={"Type": [{
        'Value': TYPE_PREFIX,    'Comparison': 'PREFIX'}],
        'RecordState': [{'Value': RECORDSTATE_ACTIVE, 'Comparison': 'EQUALS'}]})

    for previous_findings in findings_for_check_pages:
        for finding in previous_findings["Findings"]:
            if not finding['Id'] in new_ids:
                finding['UpdatedAt'] = new_recorded_time
                finding['RecordState'] = RECORDSTATE_ARCHIVED
                archived.append(finding)

    if len(archived) > 0:
        import_new_findings(archived)


def lambda_handler(event, context):
    """Lambda response to completed audit tasks"""

    logger.error("Error:  %s", json.dumps(event))

    region = os.environ['AWS_REGION']
    partition = get_partition(region)

    for record in event["Records"]:
        msg = json.loads(record['Sns']['Message'])
        new_findings = []

        try:
            if msg.get("taskType") and msg.get("auditDetails"):
                task_id = msg['taskId']
                logger.info(msg['taskId'])
                task = iot.describe_audit_task(taskId=task_id)

                audit_name = task.get("scheduledAuditName", "OnDemand")

                if (msg['taskType'] == 'ON_DEMAND_AUDIT_TASK' or msg['taskType'] == 'SCHEDULED_AUDIT_TASK') \
                        and msg['taskStatus'] == 'COMPLETED':

                    for audit in msg['auditDetails']:
                        if audit['checkRunStatus'] == "COMPLETED_NON_COMPLIANT":
                            logger.info("NON_COMPLIANT_FINDING: {}".format(
                                audit['checkName']))
                            paginator = iot.get_paginator(
                                'list_audit_findings')
                            findings_for_check_pages = paginator.paginate(
                                taskId=task_id, checkName=audit['checkName'])
                            for page in findings_for_check_pages:
                                for finding in page['findings']:
                                    if not finding['isSuppressed']:
                                        finding['RecordState'] = RECORDSTATE_ACTIVE
                                    else:
                                        finding['RecordState'] = RECORDSTATE_ARCHIVED
                                    finding['accountId'] = msg['accountId']
                                    finding['region'] = region
                                    finding['partition'] = partition
                                    finding['auditARN'] = f"arn:{partition}:iot:{region}:{msg['accountId']}:scheduledaudit/{audit_name}"
                                    logger.info(finding)
                                    new_findings.append(
                                        map_iot_dd_audit_to_security_hub(finding))

                    if new_findings:
                        import_new_findings(new_findings)
                        archive_resolved_findings(new_findings)
            else:
                logger.info("Event not related to a completed audit task")

        except Exception as error:
            logger.error("Error: %s", error)
            raise
