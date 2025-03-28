# zcash-hackathon-example

This repo contains functions to interact with near, zcash and intents.

In main of example.py there is an example of using all these functions.
Variables which should be fetched from the frontend are defined at the top of main.
You should copy all the other functions.

When adding this code you will need to make sure that the private keys of the newly created near and zcash accounts and the near account id are stored inside of the TEE.

The env file should contain credentials of the account that is used to create the near account.
```env
CREATOR_PRIVATE_KEY=ed25519:2zKLf...
CREATOR_ACCOUNT_ID=zcash-sponsor.near
```