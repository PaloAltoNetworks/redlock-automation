Onboarding tool for Redlock.io

This tool is an automation tool for onboarding AWS accounts onto Redlock.io.  This script has options for enabling CloudTrail and VPC FlowLogs as well.  These options are not required.

Installation Requires Python3 and several python packages installable via pip. https://pypi.org/project/pip/

```
pip3 install boto3
pip3 install requests
pip3 sty
pip3 install argparse
```


```

usage: Redlock Onboarding Tool [-h] [-a AWSPROFILE] [-f] [-c] [-u USERNAME]
                               [-p PASSWORD] [-o CUSTOMERNAME]
                               [-n ACCOUNTNAME]

optional arguments:
  -h, --help            show this help message and exit
  -a AWSPROFILE, --awsprofile AWSPROFILE
                        Profile name of the AWS account to configure in your
                        ~/.aws/credentials file
  -f, --vpcflowlogs     Enable VPC FlowLogs for all your VPCs for this account
  -c, --cloudtrail      Enable CloudTrail logs for the account
  -u USERNAME, --username USERNAME
                        Redlock.io username
  -p PASSWORD, --password PASSWORD
                        Redlock.io password
  -o CUSTOMERNAME, --customername CUSTOMERNAME
                        Redlock.io organization/tenant name
  -n ACCOUNTNAME, --accountname ACCOUNTNAME
                        Name for account within Redlock.io
```
