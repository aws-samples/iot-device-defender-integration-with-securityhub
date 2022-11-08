# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import os
import json
import logging
import boto3
import datetime

from more_itertools import partition

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


def get_resource_identifier(iot_finding):
    """Get resource name from IoT device Defender finding"""
    resource = iot_finding['nonCompliantResource']['resourceIdentifier']
    if list(resource.keys())[0] == "policyVersionIdentifier":
        return resource["policyVersionIdentifier"]["policyName"]
    else:
        return list(resource.values())[0]


def get_behavior_and_severity(behavior_name):
    fragments = behavior_name.split("-")
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    if len(fragments) > 1 and fragments[1] in severities:
        return fragments[0], fragments[1].upper()
    logger.warning(
        "Couldn't identify severity of behavior, using MEDIUM instead")
    return behavior_name, "MEDIUM"


def map_iot_dd_detect_to_security_hub(alarm):
    """Create a Security Hub finding based on IoT Device Defender finding"""
    behavior_name, severity = get_behavior_and_severity(
        alarm['behavior']['name'])
    resource_type = "Other"
    account_id = alarm['AccountId']
    title = f"Device {alarm['thingName']} in violation of behavior {behavior_name} from {alarm['securityProfileName']}"
    region = alarm['Region']
    partition = alarm['Partition']
    resource_id = f"arn:{partition}:iot:{region}:{account_id}:thing/{alarm['thingName']}"
    finding_id = f"arn:{partition}:iot-device-defender:{region}:{account_id}:detect/violation/{alarm['violationId']}"
    record_state = RECORDSTATE_ACTIVE
    status = "FAILED"
    if alarm['behavior']['criteria'].get('mlDetectionConfig'):
        # ML Detect
        criteria = "Confidence: {}".format(alarm['behavior']['criteria']['mlDetectionConfig']['confidenceLevel'])
    elif alarm['behavior']['criteria'].get('value'):
        # Absolute value
        criteria = "{} {}".format(alarm['behavior']['criteria']['comparisonOperator'], alarm['behavior']['criteria']['value'])
    else:
        # Relative value
        criteria = "{} {}".format(alarm['behavior']['criteria']['comparisonOperator'],
                                  alarm['behavior']['criteria']['statisticalThreshold']['statistic'])
    description = f"Device {alarm['thingName']}  showed abnormal behavior of {behavior_name} specified in {alarm['securityProfileName']} security profile. Metric {alarm['behavior']['metric']} {criteria}"
    d = datetime.datetime.utcnow()
    new_recorded_time = d.isoformat() + "Z"

    remediation_url = "https://console.aws.amazon.com/iot/home?region=" + \
        region+"#/dd/violationhub"
    new_finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": f"arn:{partition}:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": f"{alarm['securityProfileName']}/{behavior_name}",
        "AwsAccountId": account_id,
        "Compliance": {"Status": status},
        "Types": [
            f"{TYPE_PREFIX}/{alarm['securityProfileName']}-{behavior_name}"
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


def import_new_findings(new_finding):
    """Import new audit findings to Security Hub"""
    try:
        response = securityhub.batch_import_findings(Findings=[new_finding])
        if response['FailedCount'] > 0:
            logger.warning("Failed to import {} findings".format(
                response['FailedCount']))
            logger.warning(response)
        else:
            logger.info("Findings imported to Security Hub")
    except Exception as error:
        logger.error("Error:  %s", error)
        raise


def archive_finding(violation_id, state, description, region, partition, account_id):

    finding_id = f"arn:{partition}:iot-device-defender:{region}:{account_id}:detect/violation/{violation_id}"
    product_arn = f"arn:{partition}:securityhub:{region}:{account_id}:product/{account_id}/default"

    status = "NOTIFIED"
    if state in ("BENIGN_POSITIVE", "FALSE_POSITIVE"):
        status = "SUPPRESSED"

    response = securityhub.batch_update_findings(
        FindingIdentifiers=[
            {'Id':  finding_id,
             'ProductArn': product_arn
             }],
        Workflow={'Status': status}, Note={
            'Text': f"Reason: {description}",
            'UpdatedBy': 'iot-security-hub-integration'
        })

    if response.get('FailedFindings'):
        for element in response['FailedFindings']:
            logger.error("Update error - FindingId {0}".format(element["Id"]))
            logger.error(
                "Update error - ErrorCode {0}".format(element["ErrorCode"]))
            logger.error(
                "Update error - ErrorMessage {0}".format(element["ErrorMessage"]))


def lambda_handler(event, context):
    """Lambda response to completed audit tasks"""

    logger.info("Info:  %s", json.dumps(event))

    account_id = context.invoked_function_arn.split(":")[4]
    region = os.environ['AWS_REGION']
    partition = get_partition(alarm["Region"])

    try:
        if event.get("source", None) == "aws.iot":
            request_parameters = event['detail']['requestParameters']
            violation_id = request_parameters['violationId']
            state = request_parameters['verificationState']
            description = request_parameters.get(
                'verificationStateDescription')
            archive_finding(violation_id, state, description,
                            region, partition, account_id)
        else:
            for record in event["Records"]:

                alarm = json.loads(record['Sns']['Message'])
                alarm["AccountId"] = account_id
                alarm["Region"] = region
                alarm["Partition"] = partition
                if alarm["violationEventType"] == "alarm-invalidated":
                    archive_finding(
                        alarm["violationId"], alarm["verificationState"], "", region, partition, account_id)
                else:
                    finding = map_iot_dd_detect_to_security_hub(alarm)
                    import_new_findings(finding)

    except Exception as error:
        logger.error("Error: %s", error)
        raise
