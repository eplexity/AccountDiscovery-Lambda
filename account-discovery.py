from asyncore import write
from os import access
from warnings import filters
import boto3
import xlwt
import argparse
#import conf
from datetime import datetime
from datetime import date
from datetime import timedelta
import re
import itertools
import json
from io import StringIO
import csv
import os
import math

def main(event, context):
    account = boto3.client('sts').get_caller_identity().get('Account')
    process_client(account)

def process_client(account):
    workbook = xlwt.Workbook()

    rds_rows = 0
    ec2_rows = 0
    iam_user_rows = 0
    iam_role_rows = 0
    iam_group_rows = 0
    s3_rows = 0
    ebs_rows = 0 
    sns_rows = 0
    elb_rows = 0
    asg_instance_rows = 0
    asg_group_rows = 0
    waf_rows = 0
    eks_rows = 0
    api_rows = 0
    lam_rows = 0
    vpc_rows = 0
    sub_rows = 0
    tgw_rows = 0
    tgwa_rows = 0
    pwpol_rows = 0
    cred_rows = 0
    audit_rows = 0
    usg_rows = 0
        
    try:
        alias = boto3.client('iam').list_account_aliases()['AccountAliases'][0]
    except:
        alias = "None listed, assign in IAM Dashboard"

    
    tgw_arr, tgwa_arr = tgw_scrape(account, alias)
    tgw_rows = write_to_sheet(workbook, "TGW", tgw_arr, tgw_rows)
    tgwa_rows = write_to_sheet(workbook, "TGW Attachments", tgwa_arr, tgwa_rows)


    vpc_rows = write_to_sheet(workbook, "VPC", vpc_scrape(account, alias), vpc_rows)


    sub_rows = write_to_sheet(workbook, "Subnets", sub_scrape(account, alias), sub_rows)


    lam_rows = write_to_sheet(workbook, "Lambda", lam_scrape(account, alias), lam_rows)


    api_rows = write_to_sheet(workbook, "API", api_scrape(account, alias), api_rows)


    eks_rows = write_to_sheet(workbook, "EKS", eks_scrape(account, alias), eks_rows)


    waf_rows = write_to_sheet(workbook, "WAF", waf_scrape(account, alias), waf_rows)


    rds_rows = write_to_sheet(workbook, "RDS", rds_scrape(account, alias), rds_rows)


    ec2_rows = write_to_sheet(workbook, "EC2", ec2_scrape(account, alias), ec2_rows)


    usg_rows = write_to_sheet(workbook, "USG", usg_scrape(account, alias), usg_rows)


    user_details_arr, role_details_arr, group_details_arr = iam_scrape(account, alias)
    iam_user_rows = write_to_sheet(workbook, "IAM Users", user_details_arr, iam_user_rows)
    iam_role_rows = write_to_sheet(workbook, "IAM Roles", role_details_arr, iam_role_rows)
    iam_group_rows = write_to_sheet(workbook, "IAM Groups", group_details_arr, iam_group_rows)


    s3_rows = write_to_sheet(workbook, "S3", s3_scrape(account, alias), s3_rows)


    ebs_rows = write_to_sheet(workbook, "EBS", ebs_scrape(account, alias), ebs_rows)


    sns_rows = write_to_sheet(workbook, "SNS", sns_scrape(account, alias), sns_rows)


    elb_rows = write_to_sheet(workbook, "ELB", elb_scrape(account, alias), elb_rows)


    group_instance_details_arr, group_details_arr = asg_scrape(account, alias)
    asg_instance_rows = write_to_sheet(workbook, "ASG Instances", group_instance_details_arr, asg_instance_rows)
    asg_group_rows = write_to_sheet(workbook, "ASG Groups", group_details_arr, asg_group_rows)


    pwpol_rows = write_to_sheet(workbook, "Password Policy", pwpol_scrape(account, alias), pwpol_rows)


    cred_rows = write_to_sheet(workbook, "Credential Report", cred_scrape(account, alias), cred_rows)


    audit_rows = write_to_sheet(workbook, "Security Hub Report", audit_scrape(account, alias), audit_rows)

    filename = "/tmp/{0}-audit-{1}.xls".format(account, datetime.strftime(datetime.utcnow(), "%Y%m%d"))

    workbook.save(filename)
    try:
        upload_file(filename, os.getenv("S3_BUCKET"))
    except Exception as e:
        print("Error uploading file: {0}".format(e))

def usg_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('autoscaling')
    usg_details_arr = []

    for region in available_regions:
        ec2 = boto3.client('ec2', region_name=region)

        try:
            all_instances = ec2.describe_instances() 
            all_sg = ec2.describe_security_groups()

            instance_sg_set = []
            sg_set = []

            for reservation in all_instances["Reservations"] :
                for instance in reservation["Instances"]: 
                    for sg in instance["SecurityGroups"]:
                        instance_sg_set.append(sg["GroupName"]) 


            for security_group in all_sg["SecurityGroups"] :
                sg_set.append(security_group ["GroupName"])

            for sg in sg_set:
                if(sg not in instance_sg_set):
                    usg_details = {
                        "AccountNumber": account,
                        "AccountName": alias,
                        "Region": region,
                        "SecurityGroup": sg
                    }

                    usg_details_arr.append(usg_details)
                    
            
        except Exception as e:
            print("USG Error: {0}".format(e))
    
    return usg_details_arr
    
def pwpol_scrape(account, alias):
    pwpol_details_arr = []

    iam = boto3.client('iam')
    
    try:
        response = iam.get_account_password_policy()

        pwpol_details = {
            "AccountNumber": account,
            "AccountName": alias
        }

        for key, value in response["PasswordPolicy"].items():
            pwpol_details[key] = value

        pwpol_details_arr.append(pwpol_details)
    except Exception as e:
        print("Password Policy Scrape error: {0}".format(e))

    return pwpol_details_arr

def cred_scrape(account, alias):
    cred_details_arr = []

    iam = boto3.client('iam')
    
    try:
        response = iam.get_credential_report()

        cred_details = {}

        scsv = StringIO(response["Content"].decode())
        reader = csv.DictReader(scsv, delimiter=",")
        for row in reader:
            cred_details = {
                "AccountNumber": account,
                "AccountName": alias
            }
            for key, value in row.items():
                cred_details[key] = value
            cred_details_arr.append(cred_details)
        
        return cred_details_arr
    except Exception as e:
        print("Credential Scrape Error: {0}".format(e))

def audit_scrape(account, alias): 
    available_regions = boto3.Session().get_available_regions('autoscaling')
    audit_details_arr = []
    now = datetime.now()
    oneweekago = now - timedelta(days=7)

    for region in available_regions:
        audit_client = boto3.client('securityhub', region_name=region)

        try:
            filters={"Filters": {"SeverityLabel" : [{"Value": "CRITICAL", "Comparison": "EQUALS"}, {"Value": "HIGH", "Comparison": "EQUALS"}], "UpdatedAt": [{"Start": oneweekago.isoformat(), "End": now.isoformat()}]}}
            paginator = audit_client.get_paginator('get_findings').paginate(**filters)
            for page in paginator:
                for finding in page["Findings"]:

                    resource_str = ""
                    for resource in finding["Resources"]:
                        resource_str += resource["Id"] + " | "

                    resource_str = resource_str[0:len(resource_str) - 3]

                    try:
                        recommendation_str = finding["Remediation"]["Recommendation"]["Text"]
                    except:
                        recommendation_str = "No recommendation"

                    audit_details = {
                        "AccountNumber": account,
                        "AccountName": alias,
                        "Title": finding["Title"],
                        "Description": finding["Description"],
                        "Recommendation": recommendation_str,
                        "Id": finding["Id"],
                        "Severity": finding["Severity"]["Label"],
                        "Region": finding["Region"],
                        "FirstObserved": finding["CreatedAt"],
                        "LastUpdated": finding["UpdatedAt"],
                        "Resource": resource_str,
                        "WorkflowState": finding["WorkflowState"]
                    }
                    audit_details_arr.append(audit_details)

        except Exception as e:
            print("Audit Scrape Exception: {0}".format(e))
    return audit_details_arr

def tgw_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('ec2')
    
    tgw_details_arr = []
    tgwa_details_arr = []

    for region in available_regions:
        try:
            tgw_client = boto3.client('ec2', region_name=region)
            paginator = tgw_client.get_paginator('describe_transit_gateways').paginate()
            for page in paginator:
                if len(page["TransitGateways"]) > 0:
                    for tgw in page['TransitGateways']:
                        tgw_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "Region": region,
                            "TransitGatewayId": tgw["TransitGatewayId"],
                            "TransitGatewayArn": tgw["TransitGatewayArn"],
                            "State": tgw["State"],
                            "Description": tgw["Description"],
                            "CreationTime": datetime.strftime(tgw["CreationTime"], "%m/%d/%Y")
                        }
                        tgw_details_arr.append(tgw_details)
        except Exception as err:
            print("tgw Scrape Exception: {0}".format(err))

        try:
            tgwa_client = boto3.client('ec2', region_name=region)
            paginator = tgwa_client.get_paginator('describe_transit_gateway_attachments').paginate()
            for page in paginator:
                if len(page["TransitGatewayAttachments"]) > 0:
                    for tgwa in page['TransitGatewayAttachments']:
                        subnet_ids = ""
                        vpc_id = ""
                        name = ""

                        for tag in tgwa["Tags"]:
                            if tag["Key"] == "Name": 
                                name = tag["Value"]


                        if tgwa["ResourceType"] == "vpc":
                            try:
                                tgwa_vpc = tgwa_client.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[str(tgwa["TransitGatewayAttachmentId"])])["TransitGatewayVpcAttachments"][0]
                                for subnet in tgwa_vpc["SubnetIds"]:
                                    subnet_ids += subnet + " | "
                                subnet_ids = subnet_ids[0:len(subnet_ids) - 3]
                            except:
                                print("no subnets")
                            vpc_id = tgwa_vpc["VpcId"]

                        tgwa_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "Region": region,
                            "TransitGatewayId": tgwa["TransitGatewayId"],
                            "TransitGatewayAttachmentId": tgwa["TransitGatewayAttachmentId"],
                            "Name": name,
                            "ResourceType": tgwa["ResourceType"],
                            "VpcId": vpc_id,
                            "State": tgwa["State"],
                            "SubnetIds": subnet_ids,
                            "CreationTime": datetime.strftime(tgwa["CreationTime"], "%m/%d/%Y")
                        }

                        tgwa_details_arr.append(tgwa_details)
        except Exception as err:
            print("tgwa Scrape Exception: {0}".format(err))

    return tgw_details_arr, tgwa_details_arr

def vpc_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('ec2')
    
    vpc_details_arr = []

    for region in available_regions:
        try:
            vpc_client = boto3.client('ec2', region_name=region)
            paginator = vpc_client.get_paginator('describe_vpcs').paginate()
            for page in paginator:
                if len(page["Vpcs"]) > 0:
                    for vpc in page['Vpcs']:
                        try:
                            for tag in vpc["Tags"]:
                                if tag["Key"] == "Name": 
                                    name = tag["Value"]
                        except:
                            name = ""

                        route_str = ""
                        route_tables = vpc_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}])["RouteTables"]
                        for route in route_tables:
                            route_str += route["RouteTableId"] + " | "
                        
                        route_str = route_str[0:int(len(route_str))-3]

                        acl_string = ""

                        network_acls = vpc_client.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}])["NetworkAcls"]
                        for acl in network_acls:
                            acl_string += acl["NetworkAclId"] + " | "

                        acl_string = acl_string[0:int(len(acl_string))-3]
                        
                        vpc_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "Region": region,
                            "VpcId": vpc["VpcId"],
                            "VpcName": name,
                            "State": vpc["State"],
                            "CidrBlock": vpc["CidrBlock"],
                            "InstanceTenancy": vpc["InstanceTenancy"],
                            "IsDefault": vpc["IsDefault"],
                            "DhcpOptionsSet": vpc["DhcpOptionsId"],
                            "RouteTables": route_str,
                            "NetworkAcls": acl_string
                        }
                        vpc_details_arr.append(vpc_details)
        except Exception as err:
            print("vpc Scrape Exception: {0}".format(err))

    return vpc_details_arr

def sub_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('ec2')
    
    sub_details_arr = []

    for region in available_regions:
        try:
            sub_client = boto3.client('ec2', region_name=region)
            paginator = sub_client.get_paginator('describe_subnets').paginate()
            for page in paginator:
                if len(page["Subnets"]) > 0:
                    for sub in page['Subnets']:
                        try:
                            for tag in sub["Tags"]:
                                if tag["Key"] == "Name": 
                                    name = tag["Value"]
                        except:
                            name = ""

                        sub_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "Region": region,
                            "SubnetId": sub["SubnetId"],
                            "SubnetArn": sub["SubnetArn"],
                            "SubnetName": name,
                            "VpcId": sub["VpcId"],
                            "State": sub["State"],
                            "CidrBlock": sub["CidrBlock"],
                            "AvailabilityZone": sub["AvailabilityZone"],
                            "AvailabilityZoneId": sub["AvailabilityZoneId"],
                            "DefaultForAz": sub["DefaultForAz"],
                            "AvailableIpAddressCount": sub["AvailableIpAddressCount"],
                            "MapPublicIpOnLaunch": sub["MapPublicIpOnLaunch"],
                            "AssignIpv6AddressOnCreation": sub["AssignIpv6AddressOnCreation"]
                        }
                        sub_details_arr.append(sub_details)
        except Exception as err:
            print("Subnet Scrape Exception: {0}".format(err))

    return sub_details_arr

def lam_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('lambda')
    
    lam_details_arr = []

    for region in available_regions:
        try:
            lam_client = boto3.client('lambda', region_name=region)
            paginator = lam_client.get_paginator('list_functions').paginate()
            for page in paginator:
                if len(page["Functions"]) > 0:
                    for lam in page['Functions']:
                        lam_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "Region": region,
                            "FunctionName": lam["FunctionName"],
                            "FunctionArn": lam["FunctionArn"],
                            "Description": lam["Description"],
                            "Runtime": lam["Runtime"],
                            "Role": lam["Role"],
                            "CodeSize": lam["CodeSize"],
                            "LastModified": lam["LastModified"]
                        }
                        lam_details_arr.append(lam_details)
        except Exception as err:
            print("lam Scrape Exception: {0}".format(err))

    return lam_details_arr

def api_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('apigateway')
    
    api_details_arr = []

    for region in available_regions:
        try:
            api_client = boto3.client('apigateway', region_name=region)
            paginator = api_client.get_paginator('get_rest_apis').paginate()
            for page in paginator:
                if len(page["items"]) > 0:
                    for api in page['items']:
                        try:
                            description = api["description"]
                        except:
                            description = ""
                        
                        api_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "Region": region,
                            "Name": api["name"],
                            "Id": api["id"],
                            "Description": description,
                            "createdDate": datetime.strftime(api["createdDate"], "%m/%d/%Y")
                        }
                        api_details_arr.append(api_details)
        except Exception as err:
            print("api Scrape Exception: {0}".format(err))

    return api_details_arr

def eks_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('eks')
    
    eks_details_arr = []

    for region in available_regions:
        try:
            eks = boto3.client('eks', region_name=region)
            paginator = eks.get_paginator('list_clusters').paginate()
            for page in paginator:
                if len(page["clusters"]) > 0:
                    for cluster in page['clusters']:
                        eks_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "Region": region,
                            "Name": cluster
                        }
                        eks_details_arr.append(eks_details)
        except Exception as err:
            print("eks Scrape Exception: {0}".format(err))

    return eks_details_arr

def waf_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('autoscaling')

    waf_details_arr = []

    for region in available_regions:
        try:
            waf = boto3.client('wafv2', region_name=region)
            waf_arr = waf.list_web_acls(Scope='REGIONAL')
            if len(waf_arr["WebACLs"]) > 0:
                for acl in waf_arr["WebACLs"]:
                    acl_details = {
                        "AccountNumber": account,
                        "AccountName": alias,
                        "ARN": acl["ARN"],
                        "Description": acl["Description"],
                        "Name": acl["Name"],
                        "LockToken": acl["LockToken"],
                        "Id": acl["Id"]
                    }

                    waf_details_arr.append(acl_details)
        except Exception as err:
            print(err)

    return waf_details_arr

def asg_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('autoscaling')
    
    group_instance_details_arr = []
    group_details_arr = []

    for region in available_regions:
        try:
            asg = boto3.client('autoscaling', region_name=region)
            paginator = asg.get_paginator('describe_auto_scaling_instances').paginate()
            for page in paginator:
                if len(page["AutoScalingInstances"]) > 0:
                    for group_instance in page['AutoScalingInstances']:
                        try:
                            launch_template = group_instance["LaunchTemplate"]["LaunchTemplateName"]
                        except: 
                            launch_template = ""

                        try:
                            weighted_capacity = group_instance["WeightedCapacity"]
                        except: 
                            weighted_capacity = ""
                        
                        try:
                            launch_config = group_instance["LaunchConfigurationName"]
                        except:
                            launch_config = ""

                        group_instance_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "InstanceId": group_instance["InstanceId"],
                            "InstanceType": group_instance["InstanceType"],
                            "AvailabilityZone": group_instance["AvailabilityZone"],
                            "AutoScalingGroupName": group_instance["AutoScalingGroupName"],
                            "LifecycleState": group_instance["LifecycleState"],
                            "HealthStatus": group_instance["HealthStatus"],
                            "LaunchConfigurationName": launch_config,
                            "LaunchTemplateName": launch_template,
                            "ProtectedFromScaleIn": group_instance["ProtectedFromScaleIn"],
                            "WeightedCapacity": weighted_capacity,
                            "Region": region
                        }
                        group_instance_details_arr.append(group_instance_details)
        except Exception as err:
            print("ASG Instance Scrape Exception: {0}".format(err))

        try:
            asg = boto3.client('autoscaling', region_name=region)
            paginator = asg.get_paginator('describe_auto_scaling_groups').paginate()
            for page in paginator:
                if len(page["AutoScalingGroups"]) > 0:
                    for group in page['AutoScalingGroups']:
                        group_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "AutoScalingGroupName": group["AutoScalingGroupName"],
                            "AutoScalingGroupARN": group["AutoScalingGroupARN"],
                            "MinSize": group["MinSize"],
                            "MaxSize": group["MaxSize"],
                            "DesiredCapacity": group["DesiredCapacity"],
                            "AvailabilityZones": group["AvailabilityZones"],
                            "LoadBalancerNames": group["LoadBalancerNames"],
                            "TargetGroupARNs": group["TargetGroupARNs"],
                            "HealthCheckType": group["HealthCheckType"],
                            "NewInstancesProtectedFromScaleIn": group["NewInstancesProtectedFromScaleIn"],
                            "Region": region
                        }
                        group_details_arr.append(group_details)
        except Exception as err:
            print("ASG Group Scrape Exception: {0}".format(err))

    return group_instance_details_arr, group_details_arr


def elb_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('elb')
    
    elb_details_arr = []

    for region in available_regions:
        try:
            elb = boto3.client('elbv2', region_name=region)
            paginator = elb.get_paginator('describe_load_balancers').paginate()
            for page in paginator:
                if len(page["LoadBalancers"]) > 0:
                    for loadb in page['LoadBalancers']:
                        logging_enabled = False
                        elb_attributes = elb.describe_load_balancer_attributes(LoadBalancerArn=loadb["LoadBalancerArn"])["Attributes"]
                        for attribute in elb_attributes:
                            if attribute["Key"] == "access_logs.s3.enabled":
                                logging_enabled = attribute["Value"]

                        elb_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "Region": region,
                            "LoadBalancerArn": loadb["LoadBalancerArn"],
                            "DNSName": loadb["DNSName"],
                            "LoadBalancerName": loadb["LoadBalancerName"],
                            "VpcId": loadb["VpcId"],
                            "State": loadb["State"]["Code"],
                            "IpAddressType": loadb["IpAddressType"],
                            "Scheme": loadb["Scheme"],
                            "LoggingEnabled": logging_enabled,
                            "CreatedDate": datetime.strftime(loadb["CreatedTime"], "%m/%d/%Y")
                        }
                        elb_details_arr.append(elb_details)
        except Exception as err:
            print("ELB Scrape Exception: {0}".format(err))

    return elb_details_arr


def sns_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('ec2')
    
    topic_details_arr = []

    for region in available_regions:
        try:
            sns = boto3.client('sns', region_name=region)
            paginator = sns.get_paginator('list_topics').paginate()
            for page in paginator:
                if len(page["Topics"]) > 0:
                    for topic in page['Topics']:
                        topic_name = re.search(".*\d+\:(.*)$", topic["TopicArn"]).group(1)
                        topic_attributes = sns.get_topic_attributes(TopicArn=topic["TopicArn"])
                        encrypted = True if ("kms" in str(topic_attributes["Attributes"]["Policy"])) else False
                        topic_details = {
                            "AccountNumber": topic_attributes["Attributes"]["Owner"],
                            "AccountName": alias,
                            "TopicName": topic_name,
                            "TopicArn": topic["TopicArn"],
                            "Encrypted": encrypted,
                            "Region": region
                        }
                        topic_details_arr.append(topic_details)
        except Exception as err:
            print("SNS Scrape Exception: {0}".format(err))

    return topic_details_arr


def ebs_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('ec2')
    
    volume_details_arr = []

    for region in available_regions:
        try:
            ebs = boto3.client('ec2', region_name=region)
            paginator = ebs.get_paginator('describe_volumes').paginate()
            for page in paginator:
                if len(page["Volumes"]) > 0:
                    for volume in page['Volumes']:
                        volume_name = ""
                        try:
                            for tag in volume["Tags"]:
                                if tag["Key"] == "Name":
                                    volume_name = tag["Value"]
                        except:
                            print("No Tags")

                        attached_to_stopped = False
                        attached_instance = ""
                        delete_on_termination = False
                        snapshot_encrypted = False
                        hasAttachments = True if len(volume["Attachments"]) > 0 else False

                        if hasAttachments:
                            attached_instance = ebs.describe_instances(InstanceIds=[volume["Attachments"][0]["InstanceId"]])["Reservations"][0]["Instances"][0]
                            delete_on_termination = volume["Attachments"][0]["DeleteOnTermination"]
                            stopped_states = ["shutting-down", "terminated", "stopping", "stopped"]
                            if(attached_instance["State"]["Name"] in stopped_states):
                                attached_to_stopped = True
                            attached_instance = attached_instance["InstanceId"]
                            
                        if len(volume["SnapshotId"]) > 0:
                            try:
                                snapshot_encrypted = ebs.describe_snapshots(SnapshotIds=[volume["SnapshotId"]])["Snapshots"][0]["Encrypted"]
                            except:
                                print("Snapshot does not exist")

                        try:
                            kms_id = volume["KmsKeyId"]
                        except:
                            kms_id = ""

                        volume_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "VolumeId": volume["VolumeId"],
                            "VolumeName": volume_name,
                            "Attachment": attached_instance,
                            "DeleteOnTermination": delete_on_termination,
                            "AvailabilityZone": volume["AvailabilityZone"],
                            "Encrypted": volume["Encrypted"],
                            "State": volume["State"],
                            "VolumeType": volume["VolumeType"],
                            "AttachedToStoppedInstance": attached_to_stopped,
                            "KmsKeyId": kms_id,
                            "SnapshotId": volume["SnapshotId"],
                            "SnapshotEncrypted": snapshot_encrypted,
                            "Region": region
                        }
                        volume_details_arr.append(volume_details)
        except Exception as err:
            print("EBS Scrape Exception: {0}".format(err))

    return volume_details_arr


def s3_scrape(account, alias):
    bucket_details_arr = []

    try:
        s3 = boto3.client('s3')
        buckets = s3.list_buckets()
        if len(buckets["Buckets"]) > 0:
            for bucket in buckets["Buckets"]:
                try:
                    encrypted = True if s3.get_bucket_encryption(Bucket=bucket["Name"])["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"] is not None else False
                except:
                    encrypted = False
                try:
                    logging = True if len(s3.get_bucket_logging(Bucket=bucket["Name"])["LoggingEnabled"]) > 0 else False
                except: 
                    logging = False
                bucket_details = {
                    "AccountNumber": account,
                    "AccountName": alias,
                    "Name": bucket["Name"],
                    "Encrypted": str(encrypted),
                    "LoggingEnabled": str(logging),
                    "IsPubliclyAccessible": str(s3_public_check(bucket["Name"]))
                }
                bucket_details_arr.append(bucket_details)
    except Exception as err:
        print("S3 Scrape Exception: {0}".format(err))

    return bucket_details_arr


def s3_public_check(bucket_name):
    s3 = boto3.client('s3')

    public = "Non-Public"
    try:
        block = s3.get_public_access_block(Bucket=bucket_name)

        if(not block['PublicAccessBlockConfiguration']['BlockPublicAcls'] and not block['PublicAccessBlockConfiguration']['BlockPublicPolicy']):
            public = "Public"
    except:
        print("No public access block")

    try:
        if(s3.get_bucket_policy_status(Bucket=bucket_name)['PolicyStatus']['IsPublic']):
            public = "Public"
    except:
        print("No bucket policy")

    granted_perms = s3.get_bucket_acl(Bucket=bucket_name)
    for perm in granted_perms["Grants"]:
        if (perm["Grantee"] == "AllUsers" or perm["Grantee"] == "AuthenticatedUsers"):
            public = "Public"

    return public


def iam_scrape(account, alias):    
    user_details_arr = []
    role_details_arr = []
    group_details_arr = []

    try:
        iam = boto3.client('iam')
        paginator = iam.get_paginator('list_users').paginate()
        for page in paginator:
            if len(page["Users"]) > 0:
                for user in page['Users']:
                    access_keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]

                    for key in access_keys:
                        if key["Status"] == "Active": 
                            key_age = key["CreateDate"].date()
                            today = date.today()
                            active_days = today - key_age

                    try:
                        password_last_used = datetime.strftime(iam.get_user(UserName=user["UserName"])["User"]["PasswordLastUsed"], "%M/%d/%Y %H:%m:%S")
                    except:
                        password_last_used = "Programmatic"

                    mfa = iam.list_mfa_devices(UserName=user["UserName"])
                    mfa_enabled = True if len(mfa["MFADevices"]) > 0 else False
                    
                    user_details = {
                        "AccountNumber": account,
                        "AccountName": alias,
                        "UserName": user["UserName"],
                        "UserId": user["UserId"],
                        "PasswordLastUsed": password_last_used,
                        "MFAEnabled": mfa_enabled,
                        "AccessKeys": str(access_keys),
                        "ActiveKeyAge": active_days.days
                    }
                    user_details_arr.append(user_details)

        paginator = iam.get_paginator('list_roles').paginate()
        for page in paginator:
            if len(page["Roles"]) > 0:
                for role in page['Roles']:
                    iam_resourcer = boto3.resource('iam')
                    role_resource = iam_resourcer.Role(role["RoleName"])
                    try:
                        last_used = datetime.strftime(role_resource.role_last_used["LastUsedDate"], "%m/%d/%Y")
                    except:
                        last_used = ""

                    principal = ""

                    statement = role["AssumeRolePolicyDocument"]["Statement"]
                    for entity in statement:
                        if entity["Effect"] == "Allow":
                            for value in entity["Principal"].values():
                                principal = "{0}{1}, ".format(principal, value)

                    principal = principal[0:len(principal)-2]

                    role_details = {
                        "AccountNumber": account,
                        "AccountName": alias,
                        "RoleName": role["RoleName"],
                        "RoleId": role["RoleId"],
                        "TrustedEntities": principal,
                        "CreateDate": datetime.strftime(role["CreateDate"], "%m/%d/%Y"),
                        "LastActivity": last_used
                    }
                    role_details_arr.append(role_details)

        paginator = iam.get_paginator('list_groups').paginate()
        for page in paginator:
            if len(page["Groups"]) > 0:
                for group in page['Groups']:
                    group_details = {
                        "AccountNumber": account,
                        "AccountName": alias,
                        "GroupName": group["GroupName"],
                        "GroupId": group["GroupId"]
                    }
                    group_details_arr.append(group_details)

    except Exception as err:
        print("IAM Scrape Exception: {0}".format(err))

    return user_details_arr, role_details_arr, group_details_arr


def rds_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('rds')
    
    instance_details_arr = []

    for region in available_regions:
        try:
            rds = boto3.client('rds', region_name=region)
            paginator = rds.get_paginator('describe_db_instances').paginate()
            for page in paginator:
                if len(page["DBInstances"]) > 0:
                    for instance in page['DBInstances']:
                        snapshot_details = rds.describe_db_snapshots(DBInstanceIdentifier=instance["DBInstanceIdentifier"])
                        try: 
                            snapshot_encryption = snapshot_details["DBSnapshots"][0]["Encrypted"]
                        except:
                            snapshot_encryption = False

                        instance_details = {
                            "AccountNumber": account,
                            "AccountName": alias,
                            "DBInstanceIdentifier": instance["DBInstanceIdentifier"],
                            "DBInstanceClass": instance["DBInstanceClass"],
                            "Engine": instance["Engine"],
                            "Address": instance["Endpoint"]["Address"],
                            "AllocatedStorage": instance["AllocatedStorage"],
                            "VpcId": instance["DBSubnetGroup"]["VpcId"],
                            "StorageType": instance["StorageType"],
                            "StorageEncrypted": instance["StorageEncrypted"],
                            "ConfigurationEngineVersion": instance["EngineVersion"],
                            "MaintenanceWindow": instance["PreferredMaintenanceWindow"],
                            "DeletionProtection": instance["DeletionProtection"],
                            "MultiAZ": instance["MultiAZ"],
                            "PubliclyAccessible": instance["PubliclyAccessible"],
                            "Snapshot Encryption": snapshot_encryption,
                            "Region": region
                        }

                        instance_details_arr.append(instance_details)
        except Exception as err:
            print("RDS Scrape Exception: {0}".format(err))

    return instance_details_arr


def ec2_scrape(account, alias):
    available_regions = boto3.Session().get_available_regions('ec2')
    instance_details_arr = []

    for region in available_regions:
        try:
            ec2 = boto3.client('ec2', region_name=region)
            paginator = ec2.get_paginator('describe_instances').paginate()
            for page in paginator:
                if len(page["Reservations"]) > 0:
                    for reservation in page["Reservations"]:
                        for instance in reservation["Instances"]:
                            term_proc = ec2.describe_instance_attribute(InstanceId=instance["InstanceId"], Attribute='disableApiTermination')["DisableApiTermination"]["Value"]
                            instance_name = "Nameless"
                            try:
                                for tag in instance["Tags"]:
                                    if tag["Key"] == "Name":
                                        instance_name = tag["Value"]
                            except:
                                print("Tagless")

                            try:
                                key_name = instance["KeyName"]
                            except:
                                key_name = "None"

                            sg_str = ""
                            for group in instance["SecurityGroups"]:
                                sg_str += group["GroupName"] + " | "

                            sg_str = sg_str[0:len(sg_str) - 3]

                            try:
                                private_ip = instance["PrivateIpAddress"]
                            except:
                                private_ip = "None"

                            try:
                                public_ip = instance["PublicIpAddress"]
                            except:
                                public_ip = "None"
                            
                            try:
                                instance_details = {
                                    "AccountNumber": account,
                                    "AccountName": alias,
                                    "InstanceId": instance["InstanceId"],
                                    "InstanceName": instance_name,
                                    "ImageId": instance["ImageId"],
                                    "PrivateIpAddress": private_ip,
                                    "PublicIpAddress": public_ip,
                                    "VpcId": instance["VpcId"],
                                    "SubnetId": instance["SubnetId"],
                                    "SecurityGroups": sg_str,
                                    "KeyName": key_name,
                                    "State": instance["State"]["Name"],
                                    "Termination Protection": term_proc,
                                    "Region": region
                                }
                            except Exception as err:
                                instance_details = {
                                    "Account Number": reservation["OwnerId"],
                                    "AccountName": alias,
                                    "InstanceId": instance["InstanceId"],
                                    "InstanceName": instance_name,
                                    "ImageId": instance["ImageId"],
                                    "PrivateIpAddress": private_ip,
                                    "PublicIpAddress": public_ip,
                                    "VpcId": "None",
                                    "SubnetId": "None",
                                    "SecurityGroups": sg_str,
                                    "KeyName": key_name,
                                    "State": instance["State"]["Name"],
                                    "Termination Protection": term_proc,
                                    "Region": region
                                }
                            instance_details_arr.append(instance_details)
        except Exception as err:
            print("EC2 Scrape Exception: {0}".format(err))
        
    return instance_details_arr
    

def write_to_sheet(workbook, sheetName, values, num_rows):
    try:
        if(len(values) == 0):
            return num_rows
    except:
        return num_rows

    print("Opening: " + sheetName)
    values_2 = []
    iteration = math.floor(num_rows/65535)
    row_index = num_rows
    sheetName_label = sheetName
    if(iteration > 0):
        sheetName_label += "-{0}".format(str(iteration + 1))
        row_index = num_rows - (65535 * (iteration))
        print(row_index)
        print("Augment: " + sheetName_label)
    if(math.floor((num_rows + len(values))/65535) > iteration):
        print("First Length: " + str(len(values)))
        diff = (65535 * (iteration +1)) - num_rows
        values_2 = values[diff:len(values)]
        values = values[0:diff]
        print("Second Length: " + str(len(values)))
        print("Length of second values: " + str(len(values_2)))

    newSheet = False
    try:
        worksheet = workbook.add_sheet(sheetName_label)
        newSheet = True
    except:
        worksheet = get_sheet_by_name(workbook, sheetName_label)
    for x in range(0, len(values)):
        column = 0
        if x == 0 and newSheet:
            for key, value in values[x].items():
                worksheet.write(0, column, key)
                worksheet.write(1, column, str(value))
                column += 1
        else:
            for key, value in values[x].items():
                worksheet.write(x+1+row_index, column, str(value))
                column += 1

    num_rows += len(values)
    if(len(values_2) > 0):
        num_rows = write_to_sheet(workbook, sheetName, values_2, num_rows)
    print("Num Rows: " + str(num_rows))
    return num_rows

def get_sheet_by_name(book, name):
    """Get a sheet by name from xlwt.Workbook, a strangely missing method.
    Returns None if no sheet with the given name is present.
    """
    # Note, we have to use exceptions for flow control because the
    # xlwt API is broken and gives us no other choice.
    try:
        for idx in itertools.count():
            sheet = book.get_sheet(idx)
            if sheet.name == name:
                return sheet
    except IndexError:
        return None

def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except Exception as e:
        print(e)
        return False
    return True

if __name__ == "__main__":
    main()