from __future__ import print_function
from wsgiref.handlers import format_date_time
from datetime import datetime
from datetime import timedelta
from time import mktime
from hashlib import sha1
from hashlib import md5

import sys
import requests
import json
import base64
import io
import hmac
import time
import codecs
import warnings
import traceback
warnings.filterwarnings("ignore")

#=== Description ===
# Migrate Evident's Teams, Users, Disabled Signatures, and Non-Resource Suppression Rules to RedLock.
# Requires Python 3
#
# Instructions:
# 1. Enter your RedLock user credentials
# 2. Set the API URL based on where your tenant is located:
#    a. app - https://api.redlock.io
#    b. app - https://api2.redlock.io
#    c. app - https://api.eu.redlock.io 
# 3. Enter your Evident API Public Key and Secret Key
# 4. Set which RedLock assets to create
#    a. Account Groups - one per Evident Team.
#       i.  Option to define the Account Group name for specific teams
#    b. User Roles - User Roles will be created which matches the Evident user's permissions
#    c. Users - One User per Evident User.  Must create User Roles to create Users
#    d. Alert Rules - one per Cloud Account that matches an account that exists in Evident
#       i.  Option to create Alert Rules that are disabled
#       ii. Option to disable policies based on Evident disabled signatures
#       iii.Option to disable regions based on Evident regional suppressions
#       iv. Option to disable policies based on regional suppressions
#       v.  Option to disable policies based on signature suppressions
# 5. Enable or disable dry-run mode (enabled by default).  Dry-run will not actually create any assets.
#=== End Description ===

#=== Configuration ===

config = {
    # Credentials
    'redlock_username': <username>,
    'redlock_password': <password>,
    'redlock_tenant': <customer name>,
    'redlock_api_base': 'https://api.redlock.io',
    'evident_public_key': <public key>,
    'evident_secret_key': <secret key>,

    # Dry Run, output only.  Does not actually perform tasks.
    'dry_run': True, 

    # Create one Account Group per Evident Team
    'create_account_groups': True,
    # -- Update Account Groups with their respective Cloud Accounts, based on Evident External Accounts' Teams
    'overwrite_account_groups': True,
    # -- Custom Evident Team to RedLock Account Group mapping
    'team_to_account_group_mapping': {
        'Old Evident Team': 'New RedLock Team'
    },

    # Create User Roles based on Evident User and its RBAC
    'create_user_roles': True,
    # -- Overwrite existing User Roles with new Account Group IDs if role already exists
    'overwrite_user_roles': True,
    # -- Create Users based on Evident User and its RBAC.  Only runs if create_user_roles is enabled
    'create_users': False,
    # -- Overwrite existing User with their role
    'overwrite_users': False,

    # Create one Alert Rule per Cloud Account (to granuarly control which policies to run)
    # Note: If Evident teams were not migrated, the Alert Rules will choose a random Account Group that contains the Cloud Account
    'create_alert_rules': True,
    # -- Disable newly created Alert Rules
    'disable_new_alert_rules': True,
    # -- Disable policies based on disabled Evident signatures
    'migrate_disabled_signatures': True,
    # -- Disable regions based on regional suppression rules
    'migrate_suppressed_regions': True,
    # -- Disable policies based on signature suppression rules
    #    IMPORTANT: will also create additional alert rules to if suppressed signature is only for certain regions.
    #    The additional Alert Rules are to ensure those signature/policies are enabled on the unsuppressed regions.
    'migrate_suppressed_signatures': True,
    # -- Overwrite existing Alert Rules with their associated Cloud Account
    'overwrite_alert_rules': True,

    # Refresh RedLock session token timer (in minutes)
    'refresh_in': 4
}

stats = {
    'alert_rule_count': 0,
    'user_role_count': {}
}

redlock_token = ''
token_created_at = None
version = '1.6a'

global_signature_ids = [
    '7', '3', '4', '5', '6', '10', '79', '80', '81', '66', '67', '138', '136', '139', '174',
    '175', '176', '209', '213', '212', '235', '101', '109', '110', '204', '198'
]

signature_policy_mapping = {
    # AWS signatures
    'aws': {
        '1': ['683d43c9-09e4-493a-8b02-468e69c5ee85'],
        '4': ['a2107824-6ed5-4c67-9450-8b154bb1fd2b',
            'b1acdeff-4959-4c14-8a5e-2adc1016a3d5',
            'f53107a2-00b2-46fb-98a9-1f12262c7d44',
            'ef7c537b-72eb-42a7-bab7-cb2d22c76a0d',
            '168bfaa0-8c1d-427e-bfa8-4d96d82e3d83',
            '9a5813af-17a3-4058-be13-588ea00b4bfa',
            'fd4dae57-509e-4374-96d3-e136821fc3f3',
            '31626ca9-f659-4d25-9d88-fa32262bbba7',
            'a8dcc272-0b02-4534-8627-cf70ddd264c5'], 
        '5': ['478434a1-ff6c-492e-b411-c427c06291d9'],
        '6': ['50af1c0a-ab70-44dd-b6f6-3529e795131f'],
        '8': ['8f2a2ff7-b484-463d-95df-aecd038f62b0'],
        '10': ['6ea06abf-bfd3-49f2-9332-9aee02c31d58'],
        '21': ['ee7ba0f4-904b-4dfa-9a04-9344b40cba69'],
        '23': ['0dda2afe-82df-4ba5-9664-a5ba23da9754',
            '606e3f5f-52ad-4cd5-b944-11f34c7c7379'],
        '27': ['f2b80edb-79d3-4842-b86a-3bbbcfd95c98'],
        '28': ['bc6fafc0-c5f8-4ddd-b07d-0e4394c06ad0'],
        '31': ['e2a025f5-d9d1-49ae-9eca-320f8da01b60', '2066c4ed-70ad-420e-acd6-a7d6df0797eb'],
        '34': ['617b9138-584b-4e8e-ad15-7fbabafbed1a'],
        '35': ['519456f2-f9eb-407b-b32d-064f1ac7f0ca'],
        '36': ['b82f90ce-ed8b-4b49-970c-2268b0a6c2e5'],
        '37': ['ab8b6bb8-a730-4bdf-a4d5-080c01e97335'],
        '38': ['520308c5-57e3-4061-b9bf-1ce5325a2d61'],
        '39': ['f57c13b0-6303-4ab9-8a63-2791cad113e0'],
        '41': ['65daa6a0-e040-434e-aca3-9d5765c96e7c'],
        '42': ['3b642d25-4534-487a-9399-c2622754ecb5'],
        '43': ['760f2823-997e-495f-a538-5fb073c0ee78'],
        '44': ['ee03a420-89d6-4745-a0ac-98878cb56cf4'],
        '45': ['ab7f8eda-18ab-457c-b5d3-fd4f53c722bc'],
        '46': ['8dd9e369-0c09-4477-97a2-ff0d50507fe2'],
        '47': ['89cbc2f1-fcb0-48b9-be71-4cbe2d18a5f7'],
        '48': ['5599b97c-2965-4fd2-9370-927c368abd2d'],
        '49': ['a9f1b983-f216-486e-b8ea-7259764fc420'],
        '50': ['520308c5-57e3-4061-b9bf-1ce5325a2d61'],
        '51': ['14d10ad2-51df-4b07-be69-e94951cc7067'],
        '52': ['cdcd663c-e9c9-4472-9779-e5f38751524a'],
        '53': ['c2074d5a-aa28-4dde-90c1-82f528cec55e'],
        '55': ['6eaf6455-1659-4c4b-bff5-c8c7b0fda201'],
        '56': ['6eaf6455-1659-4c4b-bff5-c8c7b0fda201'],
        '67': ['88db4b66-4dec-48c0-9013-c7871d61b1c8'],
        '69': ['ee7ba0f4-904b-4dfa-9a04-9344b40cba69'],
        '70': ['886dc8ea-3c1b-4a7c-819c-610870e7042d'],
        '72': ['07ce8e54-cde9-4bc2-860c-e273c32d9f5c'],
        '73': ['7c7ba054-0fda-48da-a20a-1ace72e62d80'],
        '75': ['89ea62c1-3845-4134-b337-cc82203b8ff9'],
        '77': ['376874b1-c94e-4bf5-a5be-064d5fadee45'],
        '78': ['fed45316-6cae-4dac-aa57-fb451bacb149', '2bfc9a1e-bbad-4778-8116-99d07f1d2ba5'],
        '79': ['d9b86448-11a2-f9d4-74a5-f6fc590caeef'],
        '80': ['d9b86448-11a2-f9d4-74a5-f6fc590caeef'],
        '82': ['bf55f5c1-d05d-4e2a-bd39-560f7900be88'],
        '84': ['36a5345a-230d-438e-a04c-a287a513e3dc'],
        '86': ['cc911950-a215-4dfb-ba84-0481c36c74c8'],
        '87': ['ed8d6416-1064-4e78-9e34-02336894df44'],
        '93': ['43c42760-5283-4bc4-ac43-a80e58c4139f'],
        '96': ['2bfc9a1e-bbad-4778-8116-99d07f1d2ba5'],
        '97': ['4daa435b-fa46-457a-9359-6a4b4a43a442'],
        '100': ['34fa9efb-d18f-41e4-b93f-2f7e5378752c'],
        '101': ['a89cca38-34d1-4c4e-b2dd-17654648a1ca'],
        '102': ['98340798-8e9f-4b4e-8c34-b001307fda3a'],
        '103': ['085de1e7-7eb5-4fde-9a14-56f563c54ed3'],
        '104': ['de67bb9a-f776-4ff3-a27f-c1560cb563ce'],
        '105': ['f0235acc-737d-4a54-8d2c-a05da32663bd'],
        '107': ['bbfd1fec-c777-4265-a307-fbca4a5912e7'],
        '108': ['81a2200a-c63e-4860-85a0-b54eaa581135'],
        '109': ['366ac171-3066-46d3-a32f-df80b0a9fe56'],
        '110': ['39df6f76-fc34-4660-97a1-fc967e3abe33'],
        '111': ['4d919861-9af6-43ec-a18b-1eebf4a4daaa'],
        '112': ['fed45316-6cae-4dac-aa57-fb451bacb149'],
        '113': ['2e5e5b6e-584c-43e7-a8e1-2b66abb74da9'],
        '114': ['ca5c571e-6930-44af-a47b-ebde3ac20ca5', '75a95357-3a98-41b9-9367-5d00fb1ab5f1'],
        '115': ['40edb7ed-948e-4204-a3bb-9597b3e673f2'],
        '116': ['4779ab55-2f4b-48cf-b4a9-828165a73f77'],
        '117': ['497f7e2c-b702-47c7-9a07-f0f6404ac896'],
        '120': ['f4f65fbe-f307-43be-a526-f169bb1e38c3'],
        '122': ['dae05966-c2ac-480f-9ef5-50e91fd57782'],
        '123': ['0132bbb2-c733-4c36-9c5d-c58967c7d1a6'],
        '124': ['d65fd313-1c5c-42a1-98b2-a73bdeda19a6'],
        '125': ['bddaae74-c3ad-474d-858f-982fecac5f1b'],
        '126': ['1bb6005a-dca6-40e2-b0a6-24da968c0808'],
        '127': ['a89cca38-34d1-4c4e-b2dd-17654648a1ca'],
        '129': ['c2b84f89-7ec8-473e-a6af-404feeeb96c5'],
        '130': ['a5fe47e1-54f3-47e1-a2a3-deedfb2f70b2'],
        '131': ['2378dbf4-b104-4bda-9b05-7417affbba3f'],
        '132': ['38e3d3cf-b694-46ec-8bd2-8f02194b5040'],
        '133': ['4a37335a-64d6-4582-8dee-7d3969815f6d'],
        '134': ['b76ad441-e715-4fd0-bbc3-cd3b2bee34bf'],
        '135': ['0d07ac51-fbfe-44fe-8edb-3314c9995ee0'],
        '136': ['deb8a07d-b5d1-4105-a10b-fc94f8a34854'],
        '137': ['49f4760d-c951-40e4-bfe1-08acaa17672a'],
        '138': ['2b7e07ba-56c8-42db-8db4-a4b65f5066c4'],
        '139': ['7ca5af2c-d18d-4004-9ad4-9c1fbfcab218'],
        '140': ['566686e8-0581-4df5-ae22-5a901ed37b58'],
        '174': ['d9b86448-11a2-f9d4-74a5-f6fc590caeef'],
        '175': ['7ca5af2c-d18d-4004-9ad4-9c1fbfcab218',
            '6a34af3f-21ae-8008-0850-229761d01081'],
        '191': ['a707de6a-11b7-478a-b636-5e21ee1f6162'],
        '192': ['b858fad6-4f4a-49ec-b14e-b2c4639b3b1a'],
        '194': ['4b411b41-7f4d-4626-884e-5ba8abd2a739'],
        '195': ['7b0df373-006a-40d6-9f3d-68e6ea0bdd5d'],
        '197': ['2f33ac46-c909-4dca-8c0d-34fa2633865a'],
        '198': ['d183c5cd-6fe6-43a9-8fbf-6b4e44c84ec9'],
        '199': ['7913fcbf-b679-5aac-d979-1b6817becb22'],
        '200': ['9412cde3-bd58-4ca5-b88b-cda44c7adfa5'],
        '201': ['052c5035-c362-452d-b0dc-31aa3eff4aae'],
        '202': ['fc2c5836-3206-4ea8-8bc9-3ba34a00aac8'],
        '203': ['f8620b9a-a1eb-4491-83ba-2c85a5dd3b6a'],
        '204': ['4a719209-0c06-4f42-a33e-9f0107a76fa9'],
        '205': ['9dd6cc35-1855-48c8-86ba-0e1818ce11e2'],
        '206': ['c5305272-a732-4e8e-8427-6a9701cd2a6f'],
        '207': ['7446ad28-8502-4d71-b334-18cef8d85a2b'],
        '208': ['7c41236b-3812-4065-bc2b-57d831fbb876'],
        '210': ['7c714cb4-3d47-4c32-98d4-c13f92ce4ec5'],
        '212': ['4d39fd5d-b4c9-414b-b95b-d465d2e38540'],
        '213': ['5a63ca23-75be-4fb7-9b52-c5392dce1553'],
        '214': ['a7451ade-75eb-4e3e-b996-c2b0d5fdd329'],
        '216': ['e1d64985-045e-4a48-9a92-da1a16dcd3eb'],
        '217': ['7eb7f61e-df59-42d4-8236-7d012f278fa6'],
        '218': ['551ee7ba-edb6-468e-a018-8774da9b1e85'],
        '224': ['b675c604-e886-43aa-a60f-a9ad1f3742d3'],
        '226': ['f5b4b962-e053-4e73-94d2-c21bd2520a0d'],
        '227': ['0ee9e44a-bc0f-4eaa-9c1d-7fc4dedc7b39'],
        '232': ['3f141560-9cfc-412a-96cc-2768edfd23ad'],
        '233': ['d1fae43a-5bb6-429a-945e-fec5e8d9c662'],
        '234': ['f2c2d8e3-4e88-4887-a7af-1d0cfcad0a48'],
        '235': ['3fb665cb-d0af-42e7-ba0f-1ddccd82356b'],
        '236': ['f2a2bcf1-2966-4cb5-9230-bd39c9903a02']
    },
    
    # Azure signatures
    'azure': {
        '137': ['360ca34f-141e-4772-8e07-52d5a14f2e6f'],
        '144': ['840b4b1c-a50b-11e8-98d0-529269fb1459'],
        '145': ['a36a7170-d628-47fe-aab2-0e734702373d'],
        '146': ['3beed53c-3f2d-47b6-bb6f-95da39ff0f26'],
        '147': ['936dd3cb-a9cc-4a13-9a2c-ea5d40856072'],
        '148': ['4afdc071-53ca-4516-8a3c-d5c91345c409'],
        '149': ['5dbd0da1-cfa4-4bce-a753-56dade428bd4'],
        '150': ['a0791206-a669-4948-a845-cc735212013c'],
        '151': ['3aa12e75-d78b-4157-9eca-6049187a30d7'],
        '152': ['5826e50f-2f29-4444-9cad-3bb4e66ee3ca'],
        '154': ['4cddc286-94b0-427a-8747-7f06b51d4689'],
        '155': ['18e1dd76-9d0f-4cdb-96d4-9d01b5cd68dc'],
        '157': ['0a3f1d49-4c05-47c4-98e2-3a42b822d05b'],
        '158': ['472e08a2-c741-43eb-a3ca-e2f5cd275cf7'],
        '159': ['f48eda6b-5d66-4d73-a62e-671de3844555'],
        '160': ['ac851899-1007-48c8-842f-dddb9a38c4ba'],
        '161': ['709b47cd-6b7a-4500-b99e-a58529a6c79e'],
        '162': ['500e9f2a-1063-4066-8eea-780efa90a0d7'],
        '163': ['bc7929f8-fe70-48ec-8690-4288aa0b98ae'],
        '164': ['3784cdfd-dd25-4cf3-b506-ad77033ccc35'],
        '165': ['91a53c5d-d629-45bb-9610-fbd2cb4c6f3c'],
        '166': ['0c620876-4549-46c4-a5b3-16e86e3cefe7'],
        '168': ['7a506ab4-d0a2-48ee-a6f5-75a97f11397d'],
        '173': ['0546188d-6f21-449d-948e-677c285a5fcf'],
        '177': ['2d93f6b1-31bc-4128-a6f1-f86e5951dfb7'],
        '178': ['d3ed9388-fa76-44b7-ac6f-72503b6340e0'],
        '179': ['3fc7b5fc-9394-4cb7-9baf-aaccfd38e9d1'],
        '180': ['927d2db7-ae6f-4122-bc61-cdbc14c71d7d'],
        '181': ['5a772daf-17c0-4a20-a689-2b3ab3f33779'],
        '182': ['fde9482f-3ac2-43f6-bda2-bf2013074acd', 'f4784022-48f3-4f3b-bc16-2b7fef56aea3'],
        '183': ['bc4e467f-10fa-471e-aa9b-28981dc73e93'],
        '184': ['bfb072a7-f602-47ad-89ac-a3eb61d3427e'],
        '220': ['8bf20934-38d6-419e-9e0e-b0c7b0c1d238'],
        '223': ['56bfe7bb-ef47-4252-a335-9751a4826609'],
        '227': ['0ee9e44a-bc0f-4eaa-9c1d-7fc4dedc7b39'],
        '228': ['0280e32d-9366-4700-9763-a03be7196614'],
        '229': ['09bd0781-759c-4324-a48e-bbf2f7e17204'],
        '230': ['2436e2a8-95e6-44b7-a4ce-3f95e1a589e4'],
        '231': ['8d78bf42-4e80-4e25-89fa-5f8a7fe8ddb1'],
        '238': ['fc914428-2c9a-4240-a3a7-769b85187278'],
        '239': ['e8799768-aeda-4d42-897a-29ede5798312'],
        '240': ['f03cafde-5248-4268-91f2-f5fd784d1f42'],
        '241': ['7363990f-b1fb-42c8-ad4a-fbb06de0310d'],
        '242': ['f8ee5354-dc49-418f-8f8d-b2742ed973e4'],
        '243': ['ecef5b12-d7f2-4c9c-9198-46b90eaf2770'],
        '244': ['60c15267-5823-44ef-b36d-b074555f59ae'],
        '245': ['57ed6965-ea15-46dc-9a8a-56140ffffc29'],
        '246': ['894e9b34-082b-4c24-ac6f-bdbf44e57ac7'],
        '247': ['19f4c5f1-1785-41b6-95be-2a393f537dad'],
        '248': ['5315a853-6a6b-43eb-a771-5906f41130b8'],
        '249': ['b630ef1b-0f24-4e47-81fd-e920e24db0de'],
        '251': ['a9937384-1ee3-430c-acda-fb97e357bfcd'],
        '252': ['46e24e8c-945c-4048-91f2-800cccf54613'],
        '255': ['4169132e-ead6-4c01-b147-d2b47b443678'],
        '259': ['6c5091cc-2da3-42b3-877e-42fd7d9e85d6'],
        '260': ['4d2615bb-091e-48fd-87b7-77a277d7d2fd'],
        '261': ['0ca00469-8223-4753-a9df-4add7c37725f'],
        '262': ['0ca00469-8223-4753-a9df-4add7c37725f'],
        '263': ['c9095cf0-3233-4cf8-af1e-ce9457a3a22a'],        
        '264': ['561cd005-12dd-4bb4-b0c7-d6de31e76c69'],
        '265': ['2d5f8bcd-45da-41e8-a497-f7c70afeb5ad'],
        '267': ['96b1b8e3-6936-434f-94ab-a154cd5967d9'],        
        '277': ['c221ce81-99df-487e-8c05-4329335e9f9a']
    }
}

rl_region_codes = [
    'ca-central-1', 
    'eu-central-1', 
    'eu-west-1', 
    'eu-west-2', 
    'ap-south-1', 
    'us-east-2', 
    'us-west-2', 
    'eu-west-3', 
    'sa-east-1', 
    'ap-northeast-2', 
    'ap-southeast-1', 
    'ap-southeast-2', 
    'ap-northeast-1', 
    'us-east-1', 
    'eu-north-1',
    'australiacentral', 
    'australiacentral2', 
    'australiaeast', 
    'australiasoutheast', 
    'brazilsouth', 
    'canadacentral', 
    'canadaeast', 
    'centralindia', 
    'centralus', 
    'eastasia', 
    'eastus', 
    'eastus2', 
    'francecentral', 
    'francesouth', 
    'germanycentral', 
    'germanynorth', 
    'germanynortheast', 
    'germanywestcentral', 
    'japaneast', 
    'japanwest', 
    'koreacentral', 
    'koreasouth', 
    'northcentralus', 
    'northeurope', 
    'norwayeast', 
    'norwaywest', 
    'southafricanorth', 
    'southafricawest', 
    'southcentralus', 
    'southindia', 
    'southeastasia', 
    'switzerlandnorth', 
    'switzerlandwest', 
    'uaecentral', 
    'uaenorth', 
    'uksouth', 
    'ukwest', 
    'westcentralus', 
    'westeurope', 
    'westindia', 
    'westus', 
    'westus2', 
    'europe-west1', 
    'europe-north1', 
    'europe-west3', 
    'us-central1',
    'europe-west2', 
    'us-west2', 
    'northamerica-northeast1', 
    'asia-south1', 
    'europe-west4', 
    'us-east4', 
    'us-west1', 
    'southamerica-east1', 
    'asia-southeast1', 
    'us-east1', 
    'australia-southeast1', 
    'asia-east1', 
    'asia-northeast1']

#=== End Configuration ===

#=== Helper Methods ===

def get_rl_time_zone(ev_time_zone):
    return 'America/Los_Angeles'

def convert_team_name(team_name):
    if team_name in config['team_to_account_group_mapping']:
        return config['team_to_account_group_mapping'][team_name]
    else:
        return team_name

#=== End Helper Methods ===

#=== Evident Methods ===

def call_ev_api(action, url, data, count = 0):
    # If URL already contains domain, need to remove
    if "https://api.evident.io" in url or "https://esp.evident.io" in url:
        url = url[22:]
    
    # Construct ESP API URL
    ev_create_url = 'https://api.evident.io%s' % (url)
    
    # Create md5 hash of body
    hex = md5(data.encode('UTF-8')).hexdigest()
    data_hash = codecs.encode(codecs.decode(hex, 'hex'),
                         'base64').decode().rstrip('\n')
    
    # Find Time
    now = datetime.now()
    stamp = mktime(now.timetuple())
    dated = format_date_time(stamp)
    
    # Create Authorization Header
    canonical = '%s,application/vnd.api+json,%s,%s,%s' % (action, data_hash, url, dated)
    key_bytes= bytes(config['evident_secret_key'], 'UTF-8')
    data_bytes= bytes(canonical, 'UTF-8')

    hashed = hmac.new(key_bytes, data_bytes, sha1)
    auth = str(base64.b64encode(hashed.digest()), 'UTF-8')
    headers = {'Date': '%s' % dated,
               'Content-MD5': '%s' % data_hash,
               'Content-Type': 'application/vnd.api+json',
               'Accept': 'application/vnd.api+json',
               'Authorization': 'APIAuth %s:%s' % (config['evident_public_key'], auth)}
    
    r = requests.Request(action, ev_create_url, data=data, headers=headers)
    p = r.prepare()
    s = requests.Session()
    try:
        ask = s.send(p, timeout=10, verify=False)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        if count < 5:
            # Wait 60 seconds for every retry
            print("Timed out, retrying in %d seconds." % (60 * (count + 1)))
            time.sleep(60 * (count + 1))
            count += 1
            return call_ev_api(action, url, data, count)
        else:
            # Give-up after 5 retries
            return false
    # Weird error where response is not JSON.  Just ignore call.
    try:
        ev_response_json = ask.json()
    except Exception as e:
        if count < 5:
            # Wait 10 seconds for every retry
            print("rate limit hit, retrying in %d seconds." % (10 * (count + 1)))
            time.sleep(10 * (count + 1))
            count += 1
            return call_ev_api(action, url, data, count)
        else:
            # Give-up after 5 retries
            return false
    
    # Handle rate-limit exceptions
    if 'errors' in ev_response_json:
        for error in ev_response_json['errors']:
            print(error)
            if int(error['status']) == 429:
                if count < 5:
                    # Wait 10 seconds for every retry
                    print("rate limit hit, retrying in %d seconds." % (10 * (count + 1)))
                    time.sleep(10 * (count + 1))
                    count += 1
                    return call_ev_api(action, url, data, count)
                else:
                    # Give-up after 5 retries
                    return false
            elif int(error['status']) == 422:
                return 'already added, but lets move on'
            elif int(error['status']) == 404:
                return 'cant find, but whatever, lets move on'
            else:
                # Throw Exception and end script if any other error occurs
                raise Exception('%d - %s' % (int(error['status']), error['title']))
    
    return ev_response_json

# Helper method - get id from relationship link
# Example: http://test.host/api/v2/signatures/1003.json
# Should return 1003
def get_id(link):
    a = link.split("/")
    b = a[len(a) - 1].split(".")
    return int(b[0])

# Helper method - get page number from link
# Example: https://api.evident.io/api/v2/reports/22952488/alerts?filter%5Bstatus_eq%5D=fail&page%5Bnumber%5D=6&page%5Bsize%5D=20
# Should return 6
def get_page_number(link):
    a = link.split("page%5Bnumber%5D=")
    b = a[1].split("&")
    return int(b[0])

# Check if script should run
# Should ONLY run if authenticated user do not have Evident role
def can_proceed():
    ev_create_url = '/api/v2/organizations'
    ev_response_json = call_ev_api('GET', ev_create_url, '')

    if len(ev_response_json['data']) > 1:
        print("Do NOT run this with a Evident role user.")
        sys.exit()

# Retrieve Evident Teams
def get_ev_teams():
    print("Retrieve Evident Teams.")

    teams = {}

    next_page = '/api/v2/teams?page[size]=100'
    ev_create_url = next_page
    ev_response_json = call_ev_api('GET', ev_create_url, '')
    while (next_page != False):     
        for item in ev_response_json['data']:
            team = {}
            team['name'] = item['attributes']['name']

            # Retrieve external accounts IDs
            external_account_ids = []
            next_page2 = "%s?page[size]=100" % item['relationships']['external_accounts']['links']['related']
            ev_create_url2 = next_page2
            ev_response_json2 = call_ev_api('GET', ev_create_url2, '')
            while (next_page2 != False):    
                for item2 in ev_response_json2['data']:
                    external_account_ids.append(item2['id'])

                if 'next' in ev_response_json2['links']:
                    next_page2 = ev_response_json2['links']['next']
                    ev_create_url2 = next_page2
                    ev_response_json2 = call_ev_api('GET', ev_create_url2, '')
                else:
                    next_page2 = False   

            team['external_account_ids'] = external_account_ids

            teams[item['id']] = team

        if 'next' in ev_response_json['links']:
            next_page = ev_response_json['links']['next']
            ev_create_url = next_page
            ev_response_json = call_ev_api('GET', ev_create_url, '')
        else:
            next_page = False

    return teams

# Retrieve Evident Users
def get_ev_users():
    print("Retrieve Evident Users.")
    users = []

    next_page = '/api/v2/users?page[size]=100'
    ev_create_url = next_page
    ev_response_json = call_ev_api('GET', ev_create_url, '')
    while (next_page != False):     
        for item in ev_response_json['data']:
            user = {}
            user['first_name'] = item['attributes']['first_name']
            user['last_name'] = item['attributes']['last_name']
            user['email'] = item['attributes']['email']
            user['access_level'] = item['attributes']['access_level']
            user['time_zone'] = item['attributes']['time_zone']

            if get_id(item['relationships']['role']['links']['related']) == 2:
                user['role'] = 'manager'
            else:
                user['role'] = 'customer'

            # Retrieve teams if access level is not organization level
            if user['access_level'] != 'organization_level':
                teams = []
                # Possible for user to have no teams (no access), need to check for that
                if item['relationships']['teams']['links']['related'] is not None:
                    next_page2 = "%s?page[size]=100" % item['relationships']['teams']['links']['related']
                    ev_create_url2 = next_page2
                    ev_response_json2 = call_ev_api('GET', ev_create_url2, '')
                    while (next_page2 != False):    
                        for item2 in ev_response_json2['data']:
                            team = {
                                'name': item2['attributes']['name']
                            }
                            teams.append(team)

                        if 'next' in ev_response_json2['links']:
                            next_page2 = ev_response_json2['links']['next']
                            ev_create_url2 = next_page2
                            ev_response_json2 = call_ev_api('GET', ev_create_url2, '')
                        else:
                            next_page2 = False   

                user['teams'] = teams

            users.append(user)

        if 'next' in ev_response_json['links']:
            next_page = ev_response_json['links']['next']
            ev_create_url = next_page
            ev_response_json = call_ev_api('GET', ev_create_url, '')
        else:
            next_page = False

    return users

# Retrieve Evident External Accounts
def get_ev_external_accounts(level):
    print("Retrieve Evident External Accounts. Level of data - %s" % level)
    external_accounts = {}

    next_page = '/api/v2/external_accounts?page[size]=100'
    ev_create_url = next_page
    ev_response_json = call_ev_api('GET', ev_create_url, '')
    while (next_page != False):     
        for item in ev_response_json['data']:
            external_account = {}
            external_account['name'] = item['attributes']['name']
            external_account['provider'] = item['attributes']['provider']

            ev_create_url2 = item['relationships']['credentials']['links']['related']
            ev_response_json2 = call_ev_api('GET', ev_create_url2, '')
            if external_account['provider'] == 'amazon':
                external_account['rl_id'] = ev_response_json2['data']['attributes']['account']
            elif external_account['provider'] == 'azure':
                external_account['rl_id'] = ev_response_json2['data']['attributes']['subscription_id']
            else:
                external_account['rl_id'] = ''

            if level == 'detailed':
                print("-- %s" % external_account['name'])

                # Retrieve disabled signatures
                disabled_signature_ids = []
                next_page2 = "%s?page[size]=100" % item['relationships']['disabled_signatures']['links']['related']
                ev_create_url2 = next_page2
                ev_response_json2 = call_ev_api('GET', ev_create_url2, '')
                while (next_page2 != False):    
                    for item2 in ev_response_json2['data']:
                        disabled_signature_ids.append(item2['id'])

                    if 'next' in ev_response_json2['links']:
                        next_page2 = ev_response_json2['links']['next']
                        ev_create_url2 = next_page2
                        ev_response_json2 = call_ev_api('GET', ev_create_url2, '')
                    else:
                        next_page2 = False
                external_account['disabled_signature_ids'] = disabled_signature_ids

                # Retrieve team name
                ev_create_url2 = item['relationships']['team']['links']['related']
                ev_response_json2 = call_ev_api('GET', ev_create_url2, '')
                if 'attributes' in ev_response_json2['data']:
                    external_account['team_name'] = ev_response_json2['data']['attributes']['name']
                else:
                    external_account['team_name'] = -1

            external_accounts[item['id']] = external_account

        if 'next' in ev_response_json['links']:
            next_page = ev_response_json['links']['next']
            ev_create_url = next_page
            ev_response_json = call_ev_api('GET', ev_create_url, '')
        else:
            next_page = False

    return external_accounts

# Retrieve Evident Regions
def get_ev_regions():
    print("Retrieve Evident Regions.")
    aws_regions = {}
    azure_regions = {}

    next_page = '/api/v2/regions?page[size]=100'
    ev_create_url = next_page
    ev_response_json = call_ev_api('GET', ev_create_url, '')
    while (next_page != False):     
        for item in ev_response_json['data']:
            # Convert Evident region code to RedLock region code
            if item['attributes']['provider'] == 'amazon':
                code = item['attributes']['code'].replace("_", "-")
                aws_regions[item['id']] = code
            elif item['attributes']['provider'] == 'azure':
                code = item['attributes']['code']
                azure_regions[item['id']] = code
            else:
                continue

        if 'next' in ev_response_json['links']:
            next_page = ev_response_json['links']['next']
            ev_create_url = next_page
            ev_response_json = call_ev_api('GET', ev_create_url, '')
        else:
            next_page = False

    regions = {
        'aws': aws_regions,
        'azure': azure_regions
    }
    return regions

# Retrieve Evident Signature and Regional Suppression Rules
def get_ev_suppressions():
    print("Retrieve Evident Suppression Rules.")
    suppressions = []

    next_page = '/api/v2/suppressions?page[size]=100&filter[status_eq]=active&include=regions,external_accounts,signatures,custom_signatures'
    ev_create_url = next_page
    ev_response_json = call_ev_api('GET', ev_create_url, '')
    while (next_page != False):     
        for item in ev_response_json['data']:
            # Signature or Custom signatures are defined = not regional, skip
            #if item['relationships']['signatures']['data'] or item['relationships']['custom_signatures']['data']:
            #    continue

            suppression = {}
            suppression['id'] = item['id']
            suppression['resource'] = item['attributes']['resource']
            suppression['region_ids'] = []
            for region in item['relationships']['regions']['data']:
                suppression['region_ids'].append(region['id'])
            suppression['external_account_ids'] = []
            for external_account in item['relationships']['external_accounts']['data']:
                suppression['external_account_ids'].append(external_account['id'])
            suppression['signature_ids'] = []
            for signature in item['relationships']['signatures']['data']:
                suppression['signature_ids'].append(signature['id'])

            suppressions.append(suppression)

        if 'next' in ev_response_json['links']:
            next_page = ev_response_json['links']['next']
            ev_create_url = next_page
            ev_response_json = call_ev_api('GET', ev_create_url, '')
        else:
            next_page = False

    return suppressions

#=== End Evident Methods ===

#=== RedLock Methods ===

# Process API requests
def call_rl_api(action, url, data, count = 0):
    global redlock_token
    global token_created_at
    
    # Construct RedLock API URL
    rl_create_url = '%s%s' % (config['redlock_api_base'], url)
    
    # Authenticate
    now = datetime.now()
    if (url != '/login' and url != '/auth_token/extend'):
        if redlock_token == '' or (token_created_at + timedelta(minutes=config['refresh_in']) <= datetime.now()):
            if redlock_token == '':
                print("RedLock API Login")
            else:
                print("Token expired, re-login")
            login_info_hash = {
                'username': config['redlock_username'],
                'password': config['redlock_password'],
            }
            if config['redlock_tenant'] is not None:
                login_info_hash['customerName'] = config['redlock_tenant']
            login_info = json.dumps(login_info_hash)

            rl_response_json = call_rl_api('POST', '/login', data=login_info)
            redlock_token = rl_response_json['token']
            token_created_at = datetime.now()
    
    headers = {'Content-Type': 'application/json',
              'x-redlock-auth': redlock_token}
    
    # Prepare and issue request
    try:
        r = requests.Request(action, rl_create_url, data=data, headers=headers)  
        p = r.prepare()
        s = requests.Session()
        ask = s.send(p, timeout=(count+1) * 5, verify=False)
        # Error Handling
        if (ask.status_code != 200):
            message = ''
            if 'x-redlock-status' in ask.headers:
                message = json.loads(ask.headers['x-redlock-status'])[0]["i18nKey"]
                message = json.loads(ask.headers['x-redlock-status'])[0]["subject"]
            
                return {'message': message, 'status_code': ask.status_code}
            if (count < 5):
                print("Unexpected error: %s, retry." % ask.status_code)
                rl_response_json = call_rl_api(action, url, data, (count + 1))

            return rl_response_json
        else:
            if (ask.text != '' or not ask.text):
                rl_response_json = ask.json()
            elif 'x-redlock-status' in ask.headers:
                return {'message': ask.headers['x-redlock-status'], 'status_code': ask.status_code}
            else:
                if (count < 5):
                    rl_response_json = call_rl_api(action, url, data, (count + 1))
                else:
                    print("error, exiting")
                    sys.exit()
                    return {}

            return rl_response_json
    # Retry after timeout
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        print("Timed out, retry")
        #if (count < 10):
        rl_response_json = call_rl_api(action, url, data, (count + 1))
        return rl_response_json
        #else:
        #    raise requests.exceptions.Timeout
    except json.decoder.JSONDecodeError as e:
        if (ask.status_code == 200 and (ask.text != '' or not ask.text)):
            return {'message': '', 'status_code': 200}
        else:
            print(e)
            sys.exit()
    except Exception as e:
        print("Ran into something else")
        print(e)
        sys.exit()

    print("No exceptions but got nothing?? Let's retry")
    sys.exit()
    return {}

# Retrieve all account groups
def get_rl_account_groups():
    print("Retrieve RedLock Account Groups.")
    rl_create_url = '/cloud/group'
    rl_response_json = call_rl_api('GET', rl_create_url, '')
    return rl_response_json

# Retrieve RedLock Users
def get_rl_users():
    print("Retrieve RedLock Users.")
    rl_create_url = '/user/name'
    rl_response_json = call_rl_api('GET', rl_create_url, '')
    return rl_response_json

# Retrieve RedLock Cloud Accounts
def get_rl_cloud_accounts():
    print("Retrieve RedLock Cloud Accounts.")
    rl_create_url = '/cloud'
    rl_response_json = call_rl_api('GET', rl_create_url, '')
    return rl_response_json

# Retrieve RedLock User Roles
def get_rl_user_roles():
    print("Retrieve RedLock User Roles.")
    rl_create_url = '/user/role/name'
    rl_response_json = call_rl_api('GET', rl_create_url, '')
    return rl_response_json

# Retrieve RedLock Policy IDs
def get_rl_policy_ids():
    print("Retrieve RedLock Policy IDs.")
    rl_create_url = '/policy'
    rl_response_json = call_rl_api('GET', rl_create_url, '')
    policy_ids = []
    for item in rl_response_json:
        policy_ids.append(item['policyId'])
    return policy_ids

# Create RedLock Account Group, based on Evident team.
# If Account Group already exist, then don't do anything
def create_rl_account_group(team, cloud_account_ids):
    account_group_name = convert_team_name(team['name'])
    if config['dry_run']:
        print("Account Group %s created/updated." % account_group_name)
        print("-- Cloud Account IDs: %s" % cloud_account_ids)
        return True

    data = json.dumps({
        'name': account_group_name,
        'description': 'Created by Evident Asset Migrator.',
        'accountIds': cloud_account_ids
    })
    rl_create_url = '/cloud/group'
    rl_response_json = call_rl_api('POST', rl_create_url, data)
    if 'status_code' not in rl_response_json or rl_response_json['status_code'] == 200:
        print("Account Group %s created." % account_group_name)
        print("-- Cloud Account IDs: %s" % cloud_account_ids)
        return True
    elif rl_response_json['message'] == 'account_group_name_already_exists' or rl_response_json['message'] == 'invalid_param_value':
        print("Account Group %s already exists." % account_group_name)
    else:
        print(rl_response_json)

    return False

# Create RedLock Account Group, based on Evident team.
# If Account Group already exist, then don't do anything
def update_rl_account_group(team, cloud_account_ids, rl_account_groups):
    account_group_name = convert_team_name(team['name'])
    account_group_id = -1
    for rl_account_group in rl_account_groups:
        if account_group_name == rl_account_group['name']:
            account_group_id = rl_account_group['id']
            break

    if account_group_id != -1:
        data = json.dumps({
            'name': account_group_name,
            'description': 'Created by Evident Asset Migrator.',
            'accountIds': cloud_account_ids
        })
        rl_create_url = '/cloud/group/%s' % account_group_id
        rl_response_json = call_rl_api('PUT', rl_create_url, data)
        print("Account Group %s updated." % account_group_name)
        print("-- Cloud Account IDs: %s" % cloud_account_ids)
        return True
    else:
        print("Cannot find Account Group %s to update" % account_group_name)
    
    return False

# Create RedLock User Role
def create_rl_user_role(name, role_type, account_group_ids):
    if name in stats['user_role_count']:
        stats['user_role_count'][name] += 1
    else:
        stats['user_role_count'][name] = 1

    if config['dry_run']:
        print("User Role %s created/updated." % name)
        print("-- Role Type: %s" % role_type)
        print("-- Account Groupd IDs: %s" % account_group_ids)
        return True

    data = json.dumps({
        'name': name,
        'description': 'Created by Evident Asset Migrator.',
        'roleType': role_type,
        'accountGroupIds': account_group_ids
    })
    rl_create_url = '/user/role'
    rl_response_json = call_rl_api('POST', rl_create_url, data)
    if 'status_code' not in rl_response_json or rl_response_json['status_code'] == 200:
        print("User Role %s created." % name)
        print("-- Role Type: %s" % role_type)
        print("-- Account Groupd IDs: %s" % account_group_ids)
        return True
    elif rl_response_json['message'] == 'user_role_name_already_exists' or rl_response_json['message'] == 'invalid_param_value':
        print("User Role %s already exists." % name)
    else:
        print(rl_response_json)

    return False

# Update RedLock User Role
def update_rl_user_role(name, role_type, account_group_ids, rl_user_roles):
    role_id = -1
    for rl_user_role in rl_user_roles:
        if name == rl_user_role['name']:
            role_id = rl_user_role['id']
            break

    if role_id != -1:
        data = json.dumps({
            'name': name,
            'description': 'Created by Evident Asset Migrator.',
            'roleType': role_type,
            'accountGroupIds': account_group_ids
        })
        rl_create_url = '/user/role/%s' % role_id
        rl_response_json = call_rl_api('PUT', rl_create_url, data)
        print("User Role %s updated." % name)
        print("-- Role Type: %s" % role_type)
        print("-- Account Groupd IDs: %s" % account_group_ids)
        return True
    else:
        print("Cannot find User Role  %s to update" % name)
    
    return False

# Create RedLock User
def create_rl_user(user, role_id):
    if config['dry_run']:
        print("User %s created/updated." % user['email'])
        print("-- Name: %s %s" % (user['first_name'], user['last_name']))
        return True

    data = json.dumps({
        'email': user['email'],
        'firstName': user['first_name'],
        'lastName': user['last_name'],
        'timeZone': get_rl_time_zone(user['time_zone']),
        'roleId': role_id
    })
    rl_create_url = '/user'
    rl_response_json = call_rl_api('POST', rl_create_url, data)
    if 'status_code' not in rl_response_json or rl_response_json['status_code'] == 200:
        print("User %s created." % user['email'])
        print("-- Name: %s %s" % (user['first_name'], user['last_name']))
        return True
    elif rl_response_json['message'] == 'duplicate_user_name' or rl_response_json['status_code'] == 409:
        print("User %s already exists." % user['email'])
    else:
        print(rl_response_json)

    return False

# Create RedLock User
def update_rl_user(user, role_id, rl_users):
    found = False
    for rl_user in rl_users:
        if user['email'] == rl_user['id']:
            found = True
            break

    if found:
        data = json.dumps({
            'firstName': user['first_name'],
            'lastName': user['last_name'],
            'timeZone': get_rl_time_zone(user['time_zone']),
            'roleId': role_id
        })
        rl_create_url = '/user/%s' % user['email']
        rl_response_json = call_rl_api('PUT', rl_create_url, data)
        print("User %s updated." % user['email'])
        print("-- Name: %s %s" % (user['first_name'], user['last_name']))
        return True
    else:
        print("Cannot find User  %s to update" % user['email'])

    return False

def get_role_id(name, rl_user_roles):
    for role in rl_user_roles:
        if name == role['name']:
            return role['id']

    return False

def get_account_group_ids(rl_account_groups):
    ids = []
    for account_group in rl_account_groups:
        ids.append(account_group['id'])

    return ids

def get_account_groups_ids_by_team(ev_teams, rl_account_groups):
    ids = []
    for team in ev_teams:
        for account_group in rl_account_groups:
            if convert_team_name(team['name']) == account_group['name']:
                ids.append(account_group['id'])
                continue

    return ids

# Retrieve RedLock Alert Rules
def get_rl_alert_rules():
    print("Retrieve RedLock Alert Rules.")
    rl_create_url = '/alert/rule'
    rl_response_json = call_rl_api('GET', rl_create_url, '')
    return rl_response_json

# Create RedLock Alert Rule
def create_rl_alert_rule(name, policies, target):    
    stats['alert_rule_count'] += 1
    if not policies:
        scan_all = True
    else:
        scan_all = False

    if config['dry_run']:
        print("Alert Rule %s created/updated." % name)
        if scan_all:
            print("-- Policies: All")
        else:
            print("-- Policies: %d" % len(policies))
        if not target['regions']:
            print("-- Regions: All")
        else:
            print("-- Regions: %d" % len(target['regions']))
        return True

    data = json.dumps({
        'name': name,
        'description': 'Created by Evident Asset Migrator.',
        'enabled': True,
        'scanAll': scan_all,
        'policies': policies,
        'policyLabels': [], 
        'excludedPolicies': [], 
        'target': target, 
        'allowAutoRemediate': False, 
        'delayNotificationMs': 0, 
        'notificationChannels': [], 
    })
    rl_create_url = '/alert/rule'
    rl_response_json = call_rl_api('POST', rl_create_url, data)
    if 'status_code' not in rl_response_json or rl_response_json['status_code'] == 200:
        print("Alert Rule %s created." % name)
        if scan_all:
            print("-- Policies: All")
        else:
            print("-- Policies: %d" % len(policies))
        if not target['regions']:
            print("-- Regions: All")
        else:
            print("-- Regions: %d" % len(target['regions']))
        return True
    elif rl_response_json['message'] == 'name':
        print("Alert Rule %s already exists." % name)
    else:
        print(rl_response_json)

    return False

def disable_rl_alert_rule(name):
    if config['dry_run']:
        print("Alert Rule %s disabled." % name)
        return True

    alert_rule = False
    for rl_alert_rule in rl_alert_rules:
        if name == rl_alert_rule['name']:
            alert_rule = rl_alert_rule
            break

    if alert_rule:
        rl_create_url = '/alert/rule/%s/status/false' % alert_rule['policyScanConfigId']
        rl_response_json = call_rl_api('PATCH', rl_create_url, '')
        print("Alert Rule %s disabled." % name)
        return True
    else:
        print("Cannot find Alert Rule %s to disable" % name)

    return False

# Create RedLock Alert Rule
def update_rl_alert_rule(name, policies, target, alert_rules):
    alert_rule = False
    for rl_alert_rule in rl_alert_rules:
        if name == rl_alert_rule['name']:
            alert_rule = rl_alert_rule
            break

    if alert_rule:
        if not policies:
            scan_all = True
        else:
            scan_all = False

        data = json.dumps({
            'name': name,
            'description': 'Created by Evident Asset Migrator.',
            'enabled': True,
            'scanAll': scan_all,
            'policies': policies,
            'policyLabels': [], 
            'excludedPolicies': [], 
            'target': target, 
            'allowAutoRemediate': False, 
            'delayNotificationMs': 0, 
            'notificationChannels': [], 
        })
        rl_create_url = '/alert/rule/%s' % alert_rule['policyScanConfigId']
        rl_response_json = call_rl_api('PUT', rl_create_url, data)
        print("Alert Rule %s updated." % name)
        if scan_all:
            print("-- Policies: All")
        else:
            print("-- Policies: %d" % len(policies))
        print("-- Regions: %d" % len(target['regions']))
        return True
    else:
        print("Cannot find Alert Rule %s to update" % name)

    return False

#=== End RedLock Methods ===

# === Begin Main Script ===
if __name__ == '__main__':
    can_proceed()

    try:
        if config['dry_run']:
            print("THIS IS A DRY RUN.  NO RESOURCES WILL BE CREATED.")

        if config['create_account_groups']:
            print("Creating Account Groups.  One for each Evident Team.")
            ev_teams = get_ev_teams()
            ev_external_accounts = get_ev_external_accounts("basic")
            rl_account_groups = get_rl_account_groups()

            # Retrieve list of Cloud Account IDs
            rl_cloud_accounts = get_rl_cloud_accounts()
            all_ids = []
            for rl_cloud_account in rl_cloud_accounts:
                all_ids.append(rl_cloud_account['accountId'])

            for team_id, team in ev_teams.items():
                # Build list of Cloud Accounts to add to Account Group
                cloud_account_ids = []
                for external_account_id in team['external_account_ids']:
                    if ev_external_accounts[external_account_id]['rl_id'] in all_ids:
                        cloud_account_ids.append(ev_external_accounts[external_account_id]['rl_id'])

                # Create or update Account Group
                result = create_rl_account_group(team, cloud_account_ids)
                if config['overwrite_account_groups'] and (not result):
                    update_rl_account_group(team, cloud_account_ids, rl_account_groups)

        if config['create_user_roles']:
            print("Creating Users and User Roles.")
            rl_account_groups = get_rl_account_groups()

            # Create a role for Organization Level, Manager role users
            create_rl_user_role("System Admin", "System Admin", [])

            # Create a role for Organization Level, Customer role users
            result = create_rl_user_role("Read Only System Admin", "Account Group Read Only", get_account_group_ids(rl_account_groups))
            if config['overwrite_user_roles'] and (not result):
                # Already exist, patch role with new set of account groups
                rl_user_roles = get_rl_user_roles()
                account_group_ids = get_account_group_ids(rl_account_groups)
                update_rl_user_role("Read Only System Admin", "Account Group Read Only", account_group_ids, rl_user_roles)

            rl_users = get_rl_users()
            ev_users = get_ev_users()
            rl_user_roles = get_rl_user_roles()

            for ev_user in ev_users:
                if ev_user['access_level'] == 'organization_level':
                    if config['create_users']:
                        if ev_user['role'] == 'manager':
                            result = create_rl_user(ev_user, get_role_id("System Admin", rl_user_roles))
                        if ev_user['role'] == 'customer':
                            result = create_rl_user(ev_user, get_role_id("Read Only System Admin", rl_user_roles))
                # Check if user has one team, if so, create a team role
                else:
                    if len(ev_user['teams']) == 0:
                        print("User %s %s belongs to no teams (no access to anything), skipping." % (ev_user['first_name'], ev_user['last_name']))
                        continue
                    if len(ev_user['teams']) == 1:
                        # Create a custom role for this team
                        role_type = "Account Group Admin" if ev_user['role'] == 'manager' else "Account Group Read Only"
                        account_group_ids = get_account_groups_ids_by_team(ev_user['teams'], rl_account_groups)
                        role_name = "%s %s" % (convert_team_name(ev_user['teams'][0]['name']), role_type)
                        result = create_rl_user_role(role_name, role_type, account_group_ids)
                        if config['overwrite_user_roles'] and (not result):
                            # Already exist, patch role with new set of account groups
                            update_rl_user_role(role_name, role_type, account_group_ids, rl_user_roles)
                        else:
                            rl_user_roles = get_rl_user_roles()
                    else: 
                        # Create a custom role for this user
                        role_type = "Account Group Admin" if ev_user['role'] == 'manager' else "Account Group Read Only"
                        account_group_ids = get_account_groups_ids_by_team(ev_user['teams'], rl_account_groups)
                        role_name = "%s %s Role" % (ev_user['first_name'], ev_user['last_name'])
                        result = create_rl_user_role(role_name, role_type, account_group_ids)
                        if config['overwrite_user_roles'] and (not result):
                            # Already exist, patch role with new set of account groups
                            update_rl_user_role(role_name, role_type, account_group_ids, rl_user_roles)
                        else:
                            rl_user_roles = get_rl_user_roles()

                    # Create user
                    if config['create_users']:
                        role_id = get_role_id(role_name, rl_user_roles)
                        result = create_rl_user(ev_user, role_id)
                        if config['overwrite_users'] and (not result):
                            # Already exist, patch user with new info
                            update_rl_user(ev_user, role_id, rl_users)

        if config['create_alert_rules']:
            print("Creating Alert Rules.  One for each Cloud Account.")
            rl_cloud_accounts = get_rl_cloud_accounts()
            rl_account_groups = get_rl_account_groups()
            rl_policies = get_rl_policy_ids()
            if config['migrate_disabled_signatures']:
                ev_external_accounts = get_ev_external_accounts("detailed")
            else:
                ev_external_accounts = get_ev_external_accounts("basic")

            if config['overwrite_alert_rules']:
                rl_alert_rules = get_rl_alert_rules()

            if config['migrate_suppressed_regions'] or config['migrate_suppressed_signatures']:
                ev_regions = get_ev_regions()
                ev_suppressions = get_ev_suppressions()

                # Categorize the suppressions
                print("-- Categorize Suppressions")
                ev_regional_suppressions = []
                ev_signature_all_region_suppressions = []
                ev_signature_some_region_suppressions = []
                ev_global_signature_suppressions = []
                for suppression in ev_suppressions:
                    print("---- Assessing %s" % suppression['id'])
                    # Resource suppression, ignore
                    if suppression['resource'] != '':
                        print("------ Resource, ignored")
                        continue

                    if not suppression['signature_ids']:
                        print("------ Signature (Regional)")
                        ev_regional_suppressions.append(suppression)
                    else:
                        contains_aws_sigs = False
                        contains_azure_sigs = False
                        contains_global_sigs = False
                        contains_none_global_sigs = False
                        for signature_id in suppression['signature_ids']:
                            # Signature does not have policy mapping, ignore
                            if signature_id not in signature_policy_mapping['aws'] and signature_id not in signature_policy_mapping['azure']:
                                suppression['signature_ids'].remove(signature_id)
                                continue
                            contains_aws_sigs = signature_id in signature_policy_mapping['aws']
                            contains_azure_sigs = signature_id in signature_policy_mapping['azure']
                                
                            # Contains Global service signature
                            if signature_id in global_signature_ids:
                                contains_global_sigs = True
                            else:
                                contains_none_global_sigs = True

                        # No signatures w/ mapping, ignore
                        if not suppression['signature_ids']:
                            print("------ Suppressed Signatures have no mappings, ignore")

                        if contains_global_sigs:
                            print("------ Signature (Global)")
                            ev_global_signature_suppressions.append(suppression)
                        
                        if contains_none_global_sigs:
                            all_region = True
                            if contains_aws_sigs:
                                for region_id, code in ev_regions['aws'].items():
                                    if region_id != '9' and region_id not in suppression['region_ids']:
                                        all_region = False
                                        break
                            if contains_azure_sigs:
                                for region_id, code in ev_regions['azure'].items():
                                    if region_id != '9' and region_id not in suppression['region_ids']:
                                        all_region = False
                                        break

                            if all_region:
                                print("------ Signature (All Region)")
                                ev_signature_all_region_suppressions.append(suppression)
                            else:
                                print("------ Signature (Some Region)")
                                ev_signature_some_region_suppressions.append(suppression)

            # Create Alert Rule, one per account
            for rl_cloud_account in rl_cloud_accounts:
                # Find the relevant region codes
                if (rl_cloud_account['cloudType'] == 'aws'):
                    my_ev_regions = ev_regions['aws']
                else:
                    my_ev_regions = ev_regions['azure']

                account_group_name = False
                for ev_external_account_id, ev_external_account in ev_external_accounts.items():
                    if rl_cloud_account['accountId'] == ev_external_account['rl_id']:
                        external_account_id = ev_external_account_id
                        account_group_name = convert_team_name(ev_external_account['team_name'])
                        break
                if account_group_name:
                    account_group = False
                    for rl_account_group in rl_account_groups:
                        if rl_account_group['name'] == account_group_name:
                            account_group = rl_account_group
                            break
                    
                    if not account_group:
                        print("Can't find Account Group for Cloud Account %s, choosing a random Account Group with the Cloud Account." % rl_cloud_account['name'])
                        if len(rl_cloud_account['groups']) > 0:
                            account_group_id = rl_cloud_account['groups'][0]['id']
                            for rl_account_group in rl_account_groups:
                                if rl_account_group['id'] == account_group_id:
                                    account_group = rl_account_group
                                    break
                        else:
                            print("Account is not part of any Account Group, skipping.")
                            continue

                    ex_account_ids = account_group['accountIds'].copy()
                    ex_account_ids.remove(rl_cloud_account['accountId'])
                    cloud_type = rl_cloud_account['cloudType']

                    policies = rl_policies.copy()
                    policy_count = len(policies)
                    # Remove disabled signatures from list
                    if config['migrate_disabled_signatures']:
                        for signature_id in ev_external_account['disabled_signature_ids']:
                            if signature_id in signature_policy_mapping[cloud_type]:
                                for policy_id in signature_policy_mapping[cloud_type][signature_id]: 
                                    if policy_id in policies:
                                        policies.remove(policy_id)

                    enabled_region_codes = []
                    # Process regional suppressions
                    if config['migrate_suppressed_regions']:
                        # Find regions to disable
                        disabled_region_codes = []
                        for suppression in ev_regional_suppressions:
                            if external_account_id in suppression['external_account_ids']:
                                for region_id in suppression['region_ids']:
                                    disabled_region_codes.append(my_ev_regions[region_id])
                            else:
                                continue
                        if disabled_region_codes:
                            enabled_region_codes = rl_region_codes.copy()
                            for code in disabled_region_codes:
                                if code in enabled_region_codes:
                                    enabled_region_codes.remove(code)

                    # Process Global service suppressions
                    for suppression in ev_global_signature_suppressions:
                        if external_account_id not in suppression['external_account_ids']:
                            continue

                        # Global region not selected, won't affect global signatures, skip
                        if '9' not in suppression['region_ids']:
                            continue

                        for signature_id in suppression['signature_ids']:
                            # Global signature, remove from policies
                            if signature_id in global_signature_ids:
                                for policy_id in signature_policy_mapping[cloud_type][signature_id]: 
                                    if policy_id in policies:
                                        policies.remove(policy_id)

                    # Process Signatures (All Region) suppressions
                    for suppression in ev_signature_all_region_suppressions:
                        if external_account_id not in suppression['external_account_ids']:
                            continue

                        for signature_id in suppression['signature_ids']:
                            # Make sure it's not a global sig
                            if signature_id not in global_signature_ids:
                                for policy_id in signature_policy_mapping[cloud_type][signature_id]: 
                                    if policy_id in policies:
                                        policies.remove(policy_id)

                    # Process Signature (Some Regions) suppressions
                    signature_id_to_disabled_region_codes = {}
                    for suppression in ev_signature_some_region_suppressions:
                        if external_account_id not in suppression['external_account_ids']:
                            continue

                        for signature_id in suppression['signature_ids']:
                            # Make sure it's not a global sig
                            if signature_id not in global_signature_ids:
                                disabled_region_codes = []
                                for region_id in suppression['region_ids']:
                                    # Add this region in if it isn't globally suppressed already
                                    if my_ev_regions[region_id] in enabled_region_codes:
                                        disabled_region_codes.append(my_ev_regions[region_id])

                                # Add this entry if at least some regions are being disabled
                                if disabled_region_codes:
                                    if signature_id not in signature_id_to_disabled_region_codes:
                                        signature_id_to_disabled_region_codes[signature_id] = disabled_region_codes
                                    else:
                                        signature_id_to_disabled_region_codes[signature_id] += disabled_region_codes

                    for signature_id, disabled_region_codes in signature_id_to_disabled_region_codes.items():
                        # Check if signature is completely suppressed or not
                        # If the policy ID is still in the list, it means it wasn't removed by a disabled sig or signature suppression
                        # In that case, we need to remove it from the list, but also create an Alert Rule to enable that policy on
                        # the regions that wasn't suppressed
                        excluded_policy_ids = []
                        for policy_id in signature_policy_mapping[cloud_type][signature_id]: 
                            if policy_id in policies:
                                policies.remove(policy_id)
                                excluded_policy_ids.append(policy_id)
                        if excluded_policy_ids:
                            enabled_region_codes_2 = enabled_region_codes.copy()
                            for code in disabled_region_codes:
                                if code in enabled_region_codes_2:
                                    enabled_region_codes_2.remove(code)

                            target = {'accountGroups': [account_group['id']], 'excludedAccounts': ex_account_ids, 'regions': enabled_region_codes_2, 'tags': []}
                            alert_rule_name = "%s Alert Rule - Sig ID %s" % (rl_cloud_account['name'], signature_id)
                            result = create_rl_alert_rule(alert_rule_name, excluded_policy_ids, target)

                            if config['disable_new_alert_rules'] and result:
                                rl_alert_rules = get_rl_alert_rules()
                                disable_rl_alert_rule(alert_rule_name)

                            if config['overwrite_alert_rules'] and (not result):
                                # Already exist, patch alert rule with new info
                                update_rl_alert_rule(alert_rule_name, excluded_policy_ids, target, rl_alert_rules)

                    
                    # No policies are disabled, scan all
                    if policy_count == len(policies):
                        policies = []

                    target = {'accountGroups': [account_group['id']], 'excludedAccounts': ex_account_ids, 'regions': enabled_region_codes, 'tags': []}
                    alert_rule_name = "%s Alert Rule" % rl_cloud_account['name']
                    result = create_rl_alert_rule(alert_rule_name, policies, target)

                    if config['disable_new_alert_rules'] and result:
                        rl_alert_rules = get_rl_alert_rules()
                        disable_rl_alert_rule(alert_rule_name)

                    if config['overwrite_alert_rules'] and (not result):
                        # Already exist, patch alert rule with new info
                        update_rl_alert_rule(alert_rule_name, policies, target, rl_alert_rules)
                else:
                    print("Cloud Account %s is not configured in Evident, skipping." % rl_cloud_account['name'])
    except Exception as e:
        print("Unexpected error.")
        print(traceback.print_exc())

    if config['create_user_roles']:
        print("Created/Updated %d User Roles" % len(stats['user_role_count']))
    if config['create_alert_rules']:
        print("Created/Updated %d Alert Rules" % stats['alert_rule_count'])
    print("Asset Migrator completed.")
