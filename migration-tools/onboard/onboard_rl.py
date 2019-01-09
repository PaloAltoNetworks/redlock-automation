import boto3
import uuid
import time
import requests
import json
import logging

config = {
	'username': '',
	'password': '',
	'customerName': 'EvidentCustomerSuccessTeam',
	'accountName': 'TestAccount'
}

def main(config):
	logging.basicConfig(
		#filename='onboarding.log', 
		format='%(asctime)s %(message)s',
		level=logging.INFO
	)
	account_information = create_account_information(config['accountName'])
	launch_cloudformation_stack(account_information)
	response = register_account_with_redlock(config, account_information)
	return

def create_account_information(account_name):
	external_id = str(uuid.uuid4())
	account_id = boto3.client('sts').get_caller_identity().get('Account')
	arn = "arn:aws:iam::"+ account_id + ":role/Redlock-Service-Role"
	account_information = {
		'name': account_name,
		'external_id': external_id,
		'account_id': account_id,
		'arn': arn
	}
	return account_information

def launch_cloudformation_stack(account_information):
	cfn_client = boto3.client('cloudformation')
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

def get_auth_token(config):
	url = "https://api.redlock.io/login"
	headers = {'Content-Type': 'application/json'}
	payload = json.dumps(config)
	response = requests.request("POST", url, headers=headers, data=payload)
	token = response.json()['token']
	return token

def call_redlock_api(auth_token, action, endpoint, payload):
	url = "https://api.redlock.io/" + endpoint
	headers = {'Content-Type': 'application/json', 'x-redlock-auth': auth_token}
	payload = json.dumps(payload)
	response = requests.request(action, url, headers=headers, data=payload)
	return response

def register_account_with_redlock(config, account_information):
	token = get_auth_token(config)
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

if __name__ == '__main__':
	main(config)
