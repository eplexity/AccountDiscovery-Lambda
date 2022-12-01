# Account Discovery Lambda
## Description and Justification

This tool audits resources in AWS accounts across a wide array of services and outputs to an xls file in an S3 bucket of your choosing

## Services Audited

- RDS
- EC2
- IAM (Users, Roles, Groups)
- S3
- EBS
- SNS
- ELB
- ASG (Instances, Groups)
- WAF
- EKS
- API Gateway
- Lambda
- VPC (Subnets, Transit Gateways, Transit Gateway Attachments)
- Password Policies
- Credential Reports
- Security Hub Reports
- Unused security groups

## Execution and Usage

1. run pip3 install -r requirements.txt --target .
2. zip up all dependencies with the account-discovery.py file
3. In Cloudformation, create a new stack using the account-discovery.yaml file
4. Go to newly created lambda function and upload the zip file you created in step 2
5. Use the test functionality to run the function. At the conclusion, you will have a xls file in the s3 bucket you specified in cloudformation