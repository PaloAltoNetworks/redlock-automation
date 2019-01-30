#!/usr/bin/env python3
import boto3
import uuid
import time
import requests
import json
import logging
import pip
import sty
import argparse
from sty import fg, bg, ef, rs, Rule
import botocore
from botocore.exceptions import ClientError
                                  
from time import sleep
parser = argparse.ArgumentParser(prog='Redlock Onboarding Tool')
parser.add_argument(
    '-a',
    '--awsprofile',
    type=str,
    default="default",
    help='Profile name of the AWS account to configure in your ~/.aws/credentials file')

parser.add_argument(
    '-f',
    '--vpcflowlogs',
    default=False,
    action="store_true",
    help='Enable VPC FlowLogs for all your VPCs for this account')

parser.add_argument(
    '-c',
    '--cloudtrail',
    default=False,
    action="store_true",
    help='Enable CloudTrail logs for the account')

parser.add_argument(
    '-u',
    '--username',
    type=str,
    default=None,
    help='Redlock.io username')
parser.add_argument(
    '-p',
    '--password',
    type=str,
    default=None,
    help='Redlock.io password')

parser.add_argument(
    '-o',
    '--customername',
    type=str,
    default=None,
    help='Redlock.io organization name. Please ensure you Escape any spaces by enclosing the name in quotes eg, "Redlock Account"')

parser.add_argument(
    '-n',
    '--accountname',
    type=str,
    default=None,
    help='Name for account within Redlock.io')

parser.add_argument(
    '-t',
    '--tenant',
    type=str,
    default=None,
    help='Your Redlock.io tenant. vailable options, app or app2.')

args = parser.parse_args()
profile = args.awsprofile

iamRole=None
flowLogsPermPolicy=None
multitrails = {}
multiAlltrails = {}

session = boto3.Session(profile_name=profile)
iamClient   = session.client   ( 'iam')
ec2Client   = session.client   ( 'ec2')
ctClient    = session.client   ( 'cloudtrail')
account_id = session.client('sts').get_caller_identity().get('Account')

globalVars = {}
globalVars['tagName']               = "Redlock-flowlogs"
globalVars['Log-GroupName']         = "Redlock-flowlogs"
globalVars['IAM-RoleName']          = "Redlock-VPC-flowlogs-role"
globalVars['regions']               = [region['RegionName'] for region in ec2Client.describe_regions()['Regions']]
globalVars['username']              = args.username
globalVars['password']              = args.password
globalVars['customerName']          = args.customername
globalVars['accountname']           = args.accountname




### Create IAM Role
flowLogsTrustPolicy = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
"""

flowLogsPermissions = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}"""


S3BucketPolicy ="""{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::redlocktrails3"
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::redlocktrails3/AWSLogs/%s/*",
            "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
        }
    ]
}""" % (account_id)


def main(globalVars):
    logging.basicConfig(
        #filename='onboarding.log', 
        format='%(asctime)s %(message)s',
        level=logging.INFO
    )
    account_information = create_account_information(globalVars['accountname'])
    launch_cloudformation_stack(account_information)
    response = register_account_with_redlock(globalVars, account_information)
    if args.vpcflowlogs==True:
      setupvpc(globalVars)
    if args.cloudtrail==True:
      is_cloudtrail_enabled()
    return

def setupvpc(globalVars):
  create_iam()
  for region in globalVars['regions']:
    createCloudwatchLog(region)
    vpcs = get_vpc_list(region)

def create_account_information(account_name):
    external_id = str(uuid.uuid4())
    account_id = session.client('sts').get_caller_identity().get('Account')
    arn = "arn:aws:iam::"+ account_id + ":role/Redlock-Service-Role"
    account_information = {
        'name': account_name,
        'external_id': external_id,
        'account_id': account_id,
        'arn': arn
    }
    return account_information

def launch_cloudformation_stack(account_information):
    cfn_client = session.client('cloudformation')
    template_url = "https://s3.amazonaws.com/redlock-public/cft/rl-read-only.template"
    logging.info("Beginning creation of IAM Service Role for AWS account: " + account_information['account_id'])
    response = cfn_client.create_stack(
        StackName='Redlock-Service-Role-Stack',
        TemplateURL=template_url,
        Parameters=[
            {
                'ParameterKey': 'RedlockRoleARN',
                'ParameterValue': 'Redlock-Service-Role', 
            },
            {
                'ParameterKey': 'ExternalID',
                'ParameterValue': account_information['external_id']
            }
        ], 
        Capabilities=['CAPABILITY_NAMED_IAM'],
        OnFailure='DELETE',
        Tags=[]
    )
    stack_id = response['StackId']
    stack_status = None
    while stack_status != 'CREATE_COMPLETE':
        time.sleep(3)
        stack_info = cfn_client.describe_stacks(StackName=stack_id)['Stacks'][0]
        stack_status = stack_info['StackStatus']
        # Poll to see if stack is finished creating
        if stack_info in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'DELETE_COMPLETE']:
            exit("Stack {} Creation Failed ".format(stack_status))
        elif stack_status == 'CREATE_COMPLETE':
            logging.info("Redlock Service Role has been created in AWS account: " + account_information['account_id'])
        else:
            logging.info("Building Redlock Service Role. Current Status: {}".format(stack_status))
    return

def get_auth_token(globalVars):
    url = "https://%s.redlock.io/login" % (arg.tenant)
    headers = {'Content-Type': 'application/json'}
    payload = json.dumps(globalVars)
    response = requests.request("POST", url, headers=headers, data=payload)
    token = response.json()['token']
    return token

def call_redlock_api(auth_token, action, endpoint, payload):
    url = "https://%s.redlock.io/" %s (arg.tenant) + endpoint
    headers = {'Content-Type': 'application/json', 'x-redlock-auth': auth_token}
    payload = json.dumps(payload)
    response = requests.request(action, url, headers=headers, data=payload)
    return response

def register_account_with_redlock(globalVars, account_information):
    token = get_auth_token(globalVars)
    payload = {
        "accountId": account_information['account_id'],
        "enabled": True,
        "externalId": account_information['external_id'],
        "groupIds": [],
        "name": account_information['name'],
        "roleArn": account_information['arn']
    }
    logging.info("Adding account to Redlock")
    response = call_redlock_api(token, 'POST', 'cloud/aws', payload)
    logging.info("Account: " + account_information['name'] + " has been on-boarded to Redlock.")
    return response

def create_trail():
    print("creating S3Bucket for CloudTrail")
    s3Client    = session.client   ( 's3')
    response = s3Client.create_bucket(
      ACL="private",
      Bucket="redlocktrails3"
    )
    response = s3Client.put_bucket_policy(
      Bucket="redlocktrails3",
      Policy=S3BucketPolicy
    )
    print("creating CloudTrail")
    response = ctClient.create_trail(
      Name="RedlockTrail",
      S3BucketName="redlocktrails3",
      IsOrganizationTrail=False,
      IsMultiRegionTrail=True,
      IncludeGlobalServiceEvents=True
      )




def is_cloudtrail_enabled():
  ctenabled=False
  response = ctClient.describe_trails()
  if len(response['trailList']) != 0:
    for each in response['trailList']:
      if each[u'IsMultiRegionTrail']==True:
        multitrails.update({each['Name']: each['HomeRegion']})
    for each in multitrails:
        regionclient  = session.client   ( 'cloudtrail', region_name=multitrails[each])
        selectors = regionclient.get_event_selectors(
            TrailName=each
            )
        if selectors['EventSelectors'][0]['ReadWriteType'] == "All":
          ctenabled=True
          break
  else:
    create_trail()
    ctenabled=True

  if ctenabled==False:
    create_trail()

def create_iam():
  try:
    global iamRole 
    iamRole = iamClient.create_role( RoleName = globalVars['IAM-RoleName'] ,
                                     AssumeRolePolicyDocument = flowLogsTrustPolicy
                                    )
    print(fg.green + 'Created IAM Role' + fg.rs)

  except ClientError as e:
    if e.response['Error']['Code'] == 'EntityAlreadyExists':
      print('Role Already Exists...')


  #### Attach permissions to the role
  try:
    global flowLogsPermPolicy 
    flowLogsPermPolicy = iamClient.create_policy( PolicyName    = "flowLogsPermissions",
                                                  PolicyDocument= flowLogsPermissions,
                                                  Description   = 'Provides permissions to publish flow logs to the specified log group in CloudWatch Logs'
                                                )
    print(fg.green + 'Created IAM Policy' + fg.rs)

  except ClientError as e:
    if e.response['Error']['Code'] == 'EntityAlreadyExists':
      print(fg.red + 'Policy Already Exists...Continuing' + fg.rs)




  try:
    response = iamClient.attach_role_policy( RoleName = globalVars['IAM-RoleName'] ,
                                             PolicyArn= flowLogsPermPolicy['Policy']['Arn']
                                            )
    print(fg.green + 'Attached IAM Policy' + fg.rs)


  except ClientError as e:
    print('Unexpected error')

  sleep(10)


def createCloudwatchLog(region):
  try:
    logsClient  = session.client   ( 'logs', region_name = region )
    logGroup = logsClient.create_log_group( logGroupName = globalVars['Log-GroupName'],
                                          tags = {'Key': globalVars['tagName'] , 'Value':'Flow-Logs'}
                                          )
    print('Created CloudWatchLog in %s' % region)

  except logsClient.exceptions.ResourceAlreadyExistsException as e:
   pass

def createflowlog(region,vpc):
  try:
    ec2Client   = session.client   ( 'ec2', region_name = region )
    nwFlowLogs = ec2Client.create_flow_logs( ResourceIds              = [vpc, ],
                                           ResourceType             = 'VPC',
                                           TrafficType              = 'ALL',
                                           LogGroupName             = globalVars['Log-GroupName'],
                                           DeliverLogsPermissionArn = iamRole['Role']['Arn']
                                          )
    print('Created FlowLog in %s' % region)
  except ClientError as e:
    raise(e)






def is_flow_logs_enabled(region,vpc):
  try:
    vpc_id=vpc
    ec2Client   = session.client   ( 'ec2', region_name = region )
    response = ec2Client.describe_flow_logs(
        Filter=[
            {
                'Name': 'resource-id',
                'Values': [
                    vpc_id,
                ]
            },
        ],
    )
    if len(response[u'FlowLogs']) != 0 and response[u'FlowLogs'][0][u'LogDestinationType']==u'cloud-watch-logs': return True
    print('Previous Flowlog detected %s' % vpc_id)
  except ClientError as e:
    raise(e)




def get_vpc_list(region):
  vpcs = []
  ec2 = session.resource('ec2', region_name=region)
  vpcarray = list(ec2.vpcs.filter())
  if not vpcarray:
    pass 
  else:
    for each in vpcarray:
      if is_flow_logs_enabled(region,each.vpc_id):
        print("Flowlog exists for %s" % each.vpc_id)
      else:
        createflowlog(region,each.vpc_id)
        print("Created %s" % each.vpc_id)

if __name__ == '__main__':
    main(globalVars)
