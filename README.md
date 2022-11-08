## How to import AWS IoT Device Defender audit and detect findings into Security Hub 

In this solution, we show how you can import AWS IoT Device Defender audit and detect findings into Security Hub. You can then view and organize Internet of Things (IoT) security findings in Security Hub together with findings from other integrated AWS services, such as Amazon GuardDuty, Amazon Inspector, Amazon Macie, AWS Identity and Access Management (IAM) Access Analyzer, AWS Systems Manager, and more. You will gain a centralized security view across both enterprise and IoT types of workloads, and have an aggregated view of AWS IoT Device Defender audit findings. This solution can support AWS Accounts managed by AWS Organizations.

For more information see AWS IoT Blog  [Importing AWS IoT Device Defender audit and detect findings into Security Hub](https://aws.amazon.com/blogs/iot/importing-aws-iot-device-defender-audit-and-detect-findings-into-security-hub/) 

## Deploying with CLI

- Create or re-use existing a S3 bucket in your account where you will upload the sources.  
- Set up your AWS credential for AWS CLI, see [Configuration basics](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html)  
- Execute the deployment script `./deploy.sh s3bucket s3prefix aws-cli-profile aws-region`, where 
  - *s3bucket* is where the sources will be uploaded
  - *s3prefix* is S3 object prefix to use without slash 
  - *aws-cli-rofile* is cli profile, use default if without profile 
  - *aws-region* is the region 
Example:
` ./deploy.sh my-test-bucket mypref default eu-west-1`
 
## Deploying with LaunchStack button

 See AWS Security Blog [How to import AWS IoT Device Defender audit findings into Security Hub](https://aws.amazon.com/blogs/security/how-to-import-aws-iot-device-defender-audit-findings-into-security-hub/)

## Contributing  

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

