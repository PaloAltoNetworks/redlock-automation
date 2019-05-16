Onboarding tool for Redlock.io

This tool is an automation tool for onboarding AWS accounts onto Redlock.io.  This script has options for enabling CloudTrail and VPC FlowLogs as well.  These options are not required.

Installation Requires Python3 and several python packages installable via pip. https://pypi.org/project/pip/

```
pip3 install boto3
pip3 install requests
pip3 install sty
pip3 install argparse
```


```
usage: Redlock Onboarding Tool [-h] [-a AWSPROFILE] [-f] [-c] [-u USERNAME]
                               [-p PASSWORD] [-o CUSTOMERNAME]
                               [-n ACCOUNTNAME] [-t TENANT]

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
                        Redlock.io password (any password with special characters should be escaped with single quotes)
  -o CUSTOMERNAME, --customername CUSTOMERNAME
                        Redlock.io organization name. Please ensure you Escape
                        any spaces by enclosing the name in quotes eg,
                        "Redlock Account"
  -n ACCOUNTNAME, --accountname ACCOUNTNAME
                        Name for account within Redlock.io
  -t TENANT, --tenant TENANT
                        Your Redlock.io tenant. vailable options, app or app2.
```
