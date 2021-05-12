# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
set -e 

print_usge (){
	
	echo "Usage:   ./deploy.sh s3bucket s3prefix aws-cli-profile aws-region"
	echo "Example: ./deploy.sh mybucket blog myprofile eu-west-1"
	echo 
}


if [ -z $1 ]; then 
	echo "Error: provide as first(1) param target bucket without prefix"
	print_usge
	exit 1
else 
	bucket=$1
fi

if [ -z $2 ]; then 
	echo "Error: provide as second(2) param s3 object prefix without slash"
	print_usge
	exit 2
else 
	prefix=$2
fi

if [ -z $3 ]; then 
	echo "Error: provide as third(3) param the AWS CLI profle"
	print_usge
	exit 3
else
	profile=$3
fi

if [ -z $4 ]; then 
	echo "Error: provide as fourth(4) param the AWS region"
	print_usge
	exit 4
else
	region=$4
fi

if  [ "${bucket: -1}" = "/" ]; then 
	bucket="${bucket%%/}"
	echo "removed slash at the end of $bucket" 
fi

if  [ "${prefix: -1}" != "/" ]; then 
	prefix="${prefix}/"
	echo "added slash at the end of $prefix" 
fi

mkdir dist || echo "folder already exists"
cd src/functions/ 
rm "../../dist/lambda_functions.zip" || echo "file already exists"
zip -r  "../../dist/lambda_functions.zip"  "./"
cd ../..
aws s3 cp --exclude ".*" --recursive "./src/templates/"   "s3://${bucket}/${prefix}" --profile "$profile" --region "$region"
aws s3 cp "./dist/lambda_functions.zip"  "s3://${bucket}/${prefix}" --profile "$profile" --region "$region"
echo "resource uploaded successfully to s3://${bucket}/${prefix}"

# Add source bucket and prefix 
sed "s/{S3BucketSources}/${bucket}/" ./config/params.json | sed "s|{S3SourcesPrefix}|${prefix}|" > "./dist/tmp.param.json"
stackName="integrate-iot-defender-security-hub-stack"

#
# check if create-stack or update
#
set +e
out=$(aws cloudformation describe-stacks --stack-name $stackName --region $region --profile $profile --output text &> /dev/null )

if [ $? -eq 0 ] ; then
  CREATE_OR_UPDATE="update-stack"
else
  CREATE_OR_UPDATE="create-stack"
fi
set -e 

echo ""
echo  "going to $CREATE_OR_UPDATE"

aws cloudformation $CREATE_OR_UPDATE \
    --stack-name $stackName \
    --template-body "file://src/templates/main.yaml" \
    --parameters "file://dist/tmp.param.json" \
    --region $region \
    --profile $profile \
    --output text \
    --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM CAPABILITY_NAMED_IAM

printf "Waiting for Cloud Formation $steakName stack to finish ..."
cfStat="start"
while [[ "$cfStat" != "CREATE_COMPLETE"  ]] && [[ "$cfStat" != "UPDATE_COMPLETE" ]]
do
  sleep 3
  printf "."
  cfStat=$(aws cloudformation describe-stacks --stack-name $stackName --region $region --profile $profile  --query 'Stacks[0].[StackStatus]' --output text)
  if [ "$cfStat" = "CREATE_FAILED" ] || [[ "$cfStat" == *"ROLLBACK"* ]]
  then
    printf "\nError: Stack $stackName failed to create or update\n"
    exit 5
  fi
done
printf "\nStack $stackName created (status $cfStat) \n"
