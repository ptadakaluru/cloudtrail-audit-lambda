
# CloudTrail Audit Lambda - Deployment Guide

## Overview

This project provides an automated approach to detect and alert on AWS activity occurring in non-whitelisted regions using CloudTrail + Lambda + EventBridge + SNS, all deployed via a single CloudFormation stack.

While AWS Config can track configuration changes, it does not give real-time insight into all API activity across regions unless explicitly configured. This Lambda-based approach directly queries CloudTrail and provides:

- Near real-time analysis (every hour or configurable)
- Flexible filtering by region, service, user, and API calls
- Alerts for unexpected activity in non-approved AWS regions
- IP geolocation for context on the source of activity
- Lower cost and simpler setup than full Config + Aggregator setups

> **Note:** You’ll need access to a Linux VM or AWS CloudShell to run the setup steps.

## 1. Clone the GitHub Repository

```bash
git clone https://github.com/ptadakaluru/cloudtrail-audit-lambda.git
cd cloudtrail-audit-lambda
```

## 2. Install Prerequisites

```bash
sudo yum install -y zip
sudo yum install -y gcc zlib-devel bzip2 bzip2-devel readline-devel sqlite sqlite-devel openssl-devel xz xz-devel libffi-devel wget
curl https://pyenv.run | bash
export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
pyenv install 3.12.0
pyenv global 3.12.0
pip install --upgrade pip
```

## 3. Install and Configure AWS CLI

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws configure [ please configure your AWS access key and secret key here. This user should have access to create s3 bucket, update s3 bucket policies and create cloudformation template]
```

## 4. CloudFormation Template Overview

This template creates:

- Lambda function with Python 3.13
- Lambda layer with `requests` library
- IAM Role with access to CloudTrail, EC2 regions, SNS, logs
- SNS Topic for alerts
- Email subscription to receive alerts
- EventBridge Rule to trigger Lambda on a schedule
- CloudWatch Alarm on Lambda failures

## 5. Python Script Explanation

The script:

- Reads CloudTrail events across all AWS regions
- Filters out whitelisted regions and known service activity
- Looks up geolocation of source IP
- Sends an alert via SNS if unauthorized region activity is detected

## 6. Setup Environment Variables

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="cloudtrail-audit-lambda-${ACCOUNT_ID}" [ change the bucket name here as per your requirements ]
REGION="us-west-2" [ change the bucket region as per your requirements ]
```

## 7. Create the S3 Bucket

```bash
aws s3api create-bucket --bucket "$BUCKET_NAME" --region "$REGION" --create-bucket-configuration LocationConstraint="$REGION"
```

## 8. Block Public Access

```bash
aws s3api put-public-access-block   --bucket "$BUCKET_NAME"   --public-access-block-configuration   BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

## 9. Upload Lambda Files to S3

```bash
cd cloudtrail-audit-lambda/lambda
aws s3 cp lambda_function.zip s3://$BUCKET_NAME/cloudtrail-audit/
aws s3 cp requests-layer.zip s3://$BUCKET_NAME/cloudtrail-audit/
```

## 10. Deploy CloudFormation Template

```bash
cd cloudtrail-audit-lambda
aws cloudformation deploy   --template-file template.yaml   --stack-name cloudtrail-audit-lambda-stack   --capabilities CAPABILITY_NAMED_IAM   --parameter-overrides     CodeS3Bucket=$BUCKET_NAME     CodeS3Key=cloudtrail-audit/lambda_function.zip     LayerS3Bucket=$BUCKET_NAME     LayerS3Key=cloudtrail-audit/requests-layer.zip     WhitelistedRegions="us-east-1,us-west-2"     HoursBack=6     ScheduleRateMinutes=60     NotificationEmail=your@email.com

[ update the email address to which you are looking forward to receive email alerts ]
[ update the ScheduleRateMinutes as per your requirements ]
[ update the WhitelistedRegions as per your requirements. You can list multiple ]
[ update the HoursBack as per your requirement. This is the time period of cloudtrial logs to search ]
```

## 11. Validate Deployed Resources

Check in AWS Console for:

- Lambda function
- IAM role with CloudTrail, EC2, SNS, Logs access
- SNS topic and email subscription
- EventBridge rule
- CloudWatch alarm for Lambda errors

## 12. Confirm Email Subscription

- You will receive an SNS email to confirm subscription
- Click "Confirm Subscription"
- You can later extend this to send alerts to SMS, HTTPS endpoints, or log ingestion platforms like ELK
