# VPC FlowLog Creation Script

Redlock script for creating VPC FlowLogs, IAM Role/policy and CloudWatch logs for VPCFlowLog ingestion within redlock.io
The script will check to see if any valid logs already exist and skip those regions where appropriate.

This tool is written in Python3

If you need to install python, you can get more information at [Python's Page](https://www.python.org/).  I also highly recommend you install the [PIP package manager for Python](https://pypi.python.org/pypi/pip) if you do not already have it installed.

To set up your python environment, you will need the following packages:
- argparse
- boto3
- sty

These can be installed on most platforms with the following commands.

``` 
pip3 install argparse
pip3 install boto3
pip3 install sty
```


# Usage

./flowlogs.py --profile=\<AWS profile\>

   profile  - Profile name of the AWS account stored in ~/.aws/credentials file
