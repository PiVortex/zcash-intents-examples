from py_near.providers import JsonProvider
from py_near.account import Account
from py_near.dapps.core import NEAR
from dotenv import load_dotenv
from typing import TypedDict, List, Dict, Union
import near_api
import os
import nacl.signing
import base64
import random
import base58
import asyncio
import requests
import json

RPC_URL = "https://free.rpc.fastnear.com"
INTENTS_RPC_URL = "https://solver-relay-v2.chaindefuser.com/rpc"
GAS = 300 * 10 ** 12
    


async def generate_nonce():
    nonce = base64.b64encode(random.getrandbits(256).to_bytes(32, byteorder='big')).decode('utf-8')
    return nonce

async def publish_intent(account_id, signer):
    standard = "nep413"
    recipient = "intents.near"
    
    # Get the quote first
    quote = await get_intent_quote(0.01)
    print("Actual amount out: ", float(quote['amount_out']) / 10 ** 8)
    
    message = {
        "signer_id": account_id,  
        "deadline": quote["expiration_time"],
        "intents": [
            {
                "intent": "token_diff",
                "diff": {
                    quote["defuse_asset_identifier_in"]: f"-{quote['amount_in']}",
                    quote["defuse_asset_identifier_out"]: f"{quote['amount_out']}"
                }
            }
        ]
    }    
    # Serialize the message to a JSON string
    message_str = json.dumps(message)
    
    nonce = await generate_nonce()

    # Create the payload
    payload = {
        "message": message_str,
        "nonce": nonce,
        "recipient": recipient
    }

    # Sign the payload
    json_payload = json.dumps(payload)
    payload_data = json_payload.encode('utf-8')
    signature = 'ed25519:' + base58.b58encode(signer.sign(payload_data)).decode('utf-8')
    public_key = 'ed25519:' + base58.b58encode(signer.public_key).decode('utf-8')

    # Construct the final intent
    intent = {
        "id": "dontcare",
        "jsonrpc": "2.0",
        "method": "publish_intent",
        "params": [
            {
                "quote_hashes": [quote["quote_hash"]],
                "signed_data": {
                    "standard": standard,
                    "payload": payload,
                    "signature": signature,
                    "public_key": public_key
                }
            }
        ]
    }

    print("Final intent:", json.dumps(intent, indent=2))
    return intent

async def register_pub_key(account, public_key):
    result = await account.view_function("intents.near", "has_public_key", {
        "account_id": account.account_id,
        "public_key": public_key
    })
    is_pub_key = result.result
    if not is_pub_key:
        await account.function_call("intents.near", "add_public_key", {
            "public_key": public_key
        }, GAS, 1)  

async def register_near_storage(account):
    account_id = account.account_id;
    result = await account.view_function("wrap.near", "storage_balance_of", {'account_id': account_id})
    balance = result.result
    if not balance:
        await account.function_call("wrap.near", "storage_deposit", {
            "account_id": account_id,
        }, GAS, 1250000000000000000000)

async def deposit_near(account, amount):
    await register_near_storage(account)
    # amount is in NEAR
    yocto_amount = int(amount * 10 ** 24)
    # Swap to wrapped NEAR
    result = await account.function_call("wrap.near", "near_deposit", {}, GAS, yocto_amount)
    # Transfer to intents
    result = await account.function_call("wrap.near", "ft_transfer_call", {
        "receiver_id": "intents.near",
        "amount": str(yocto_amount),
        "msg": "",
    }, GAS, 1)

async def get_intent_quote(amount_in):
    amount_in_yocto = str(int(amount_in * 10 ** 24))
    body = {
        "id": "dontcare",
        "jsonrpc": "2.0",
        "method": "quote",
        "params": [
            {
                "defuse_asset_identifier_in": "nep141:wrap.near",
                "defuse_asset_identifier_out": "nep141:zec.omft.near",
                "exact_amount_in": amount_in_yocto,
            }
        ]
    }

    response = requests.post(
        INTENTS_RPC_URL,
        json=body,  # requests will automatically handle JSON serialization
        headers={
            "Content-Type": "application/json"
        }
    )

    # Check if request was successful
    if not response.ok:
        raise Exception(
            f"Request failed {response.status_code} {response.reason} - {response.text}"
        )

    json_response = response.json()
    result = json_response["result"]

    if result is None:
        quote = None
    else:
        quote = result[0]

    return quote

async def create_new_near_account():
    # Load environment variables from .env file
    load_dotenv()

    # Get private key for creator account from environment variable
    private_key = os.getenv('CREATOR_PRIVATE_KEY')
    if not private_key:
        raise ValueError("CREATOR_PRIVATE_KEY not found in .env file")

    # Account id here is the account that will create the new account
    account = Account(account_id="zcash-sponsor.near", private_key=private_key, rpc_addr=RPC_URL)
    await account.startup()

    # Generate a new ed25519 key pair for the new NEAR account
    new_key = nacl.signing.SigningKey.generate()
    new_public_key = new_key.verify_key.encode()
    new_private_key = new_key.encode()

    # Convert the public key to NEAR format (base58 encoded)
    near_public_key = f"ed25519:{base58.b58encode(new_public_key).decode('ascii')}"

    # Create the new account with the generated public key
    # 0.02 NEAR = 20000000000000000000000 yoctoNEAR
    initial_balance = 20000000000000000000000  # 0.02 NEAR in yoctoNEAR
    new_account_id = "account1.zcash-sponsor.near" # Account id for the new NEAR account
    res = await account.create_account(
        account_id=new_account_id,
        public_key=near_public_key,
        initial_balance=initial_balance
    )

    # Print the new account's key pair (you should save these securely)
    print(f"New account public key: {near_public_key}")
    # Format private key according to NEAR's requirements
    new_account_private_key = f"ed25519:{base58.b58encode(new_private_key + new_public_key).decode('ascii')}"
    print(f"New account private key: {new_account_private_key}")

    # Create a new account object for the newly created account
    new_account = Account(
        account_id=new_account_id,  # Use the same account ID as created
        private_key=new_account_private_key,
        rpc_addr=rpc
    )
    await new_account.startup()

async def use_intents():
    load_dotenv()

    # Get private key for creator account from environment variable
    private_key = os.getenv('CREATOR_PRIVATE_KEY')
    public_key = os.getenv('CREATOR_PUBLIC_KEY')
    if not private_key:
        raise ValueError("CREATOR_PRIVATE_KEY not found in .env file")
    if not public_key:
        raise ValueError("CREATOR_PUBLIC_KEY not found in .env file")

    # account = Account(account_id="zcash-sponsor.near", private_key=private_key, rpc_addr=RPC_URL)
    # await account.startup()

    # # Register intent public key
    # try:
    #     await register_pub_key(account, public_key)
    # except Exception as e:
    #     print(e)

    # # Deposit 0.01 NEAR into the intents contract
    # try:
    #     await deposit_near(account, 0.01)
    # except Exception as e:
    #     print(e)

    account_id = "zcash-sponsor.near"
    key_pair = near_api.signer.KeyPair(private_key)
    signer = near_api.signer.Signer(account_id, key_pair)
    await publish_intent(account_id, signer)

async def main():
    await use_intents()



if __name__ == "__main__":
    asyncio.run(main())
