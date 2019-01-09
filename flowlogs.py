#!/usr/bin/env python3

import pip
try: import boto3
except ImportError:
    from pip._internal import main as pip
    pip(['install', '--user', 'boto3'])
    import boto3
try: import sty
except ImportError:
    from pip._internal import main as pip
    pip(['install', '--user', 'sty'])
    import sty
from sty import fg, bg, ef, rs, Rule
from botocore.exceptions import ClientError
from time import sleep

iamRole=None
flowLogsPermPolicy=None
session = boto3.Session(profile_name='default')
iamClient   = session.client   ( 'iam')
ec2Client   = session.client   ( 'ec2')





globalVars = {}
globalVars['tagName']               = "Redlock-flowlogs"
globalVars['Log-GroupName']         = "Redlock-flowlogs"
globalVars['IAM-RoleName']          = "Redlock-VPC-flowlogs-role"
globalVars['regions']               = [region['RegionName'] for region in ec2Client.describe_regions()['Regions']]


def main(globalVars):
  create_iam()
  for region in globalVars['regions']:
    createCloudwatchLog(region)
    vpcs = get_vpc_list(region)





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

#### Create the role with trust policy
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

  except ClientError as e:
    raise(e)


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
