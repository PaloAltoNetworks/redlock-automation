<h2>Asset Migrator Tool for Redlock.io</h2>

Migrate Evident's Team, User, Disabled Signatures, and Regional Suppression Rules to RedLock.

Requires Python 3

<h3>Instructions:</h3>

Modify the configuration within the script:

1. Enter your RedLock user credentials
2. Enter your Evident API Public Key and Secret Key
3. Set which RedLock assets to create
   - Account Groups - one per Evident Team.
   - Users and User Roles - One User and User Role per Evident User
   - Alert Rules - one per Cloud Account that matches an account that exists in Evident
     - Option to disable policies based on Evident disabled signatures
     - Option to disable regions based on Evident regional suppressions
4. Enable or disable dry-run mode (enabled by default).  Dry-run will not actually create any assets.

Run command: `python3 asset_migrator.py` 
