<h2>Asset Migrator Tool for Redlock.io</h2>

Migrate Evident's Teams, Users, Disabled Signatures, and Non-Resource Suppression Rules to RedLock.

Requires Python 3

<h3>Instructions:</h3>

Modify the configuration within the script:

1. Enter your RedLock user credentials
2. Set the API URL based on where your tenant is located:
  - app - https://api.redlock.io
  - app - https://api2.redlock.io
  - app - https://api.eu.redlock.io 
3. Enter your Evident API Public Key and Secret Key
4. Set which RedLock assets to create
  - Account Groups - one per Evident Team.
    -  Option to define the Account Group name for specific teams
  - User Roles - User Roles will be created which matches the Evident user's permissions
  - Users - One User per Evident User.  Must create User Roles to create Users
  - Alert Rules - one per Cloud Account that matches an account that exists in Evident
    - Option to create Alert Rules that are disabled
    - Option to disable policies based on Evident disabled signatures
    - Option to disable regions based on Evident regional suppressions
    - Option to disable policies based on regional suppressions
    - Option to disable policies based on signature suppressions
5. Enable or disable dry-run mode (enabled by default).  Dry-run will not actually create any assets.

Run command: `python3 asset_migrator.py` 
