from py_near.providers import JsonProvider
from py_near.account import Account
from py_near.dapps.core import NEAR
from dotenv import load_dotenv
import os
import nacl.signing
import base58
import asyncio
import requests
import json

RPC_URL = "https://free.rpc.fastnear.com"
INTENTS_RPC_URL = "https://solver-relay-v2.chaindefuser.com/rpc"
GAS = 300 * 10 ** 12

# class IntentRequest(object):
#     """IntentRequest is a request to perform an action on behalf of the user."""
    
#     def __init__(self, request=None, thread=None, min_deadline_ms=120000):
#         self.request = request
#         self.thread = thread
#         self.min_deadline_ms = min_deadline_ms
#         self._asset_in = None
#         self._asset_out = None

#     def set_asset_in(self, asset_name, amount):
#         """Set the input asset and amount."""
#         if amount is None:
#             raise ValueError("Input amount cannot be None")
        
#         decimals_amount = str(int(amount * 10 ** 24))  # Convert to string after calculation
#         self._asset_in = {
#             "asset": "nep141:wrap.near",
#             "amount": decimals_amount
#         }
#         return self

#     def set_asset_out(self, asset_name, amount=None):
#         """Set the output asset and optional amount."""
#         if amount is not None:
#             decimals_amount = str(int(amount * 10 ** 18))
#         else:
#             decimals_amount = None
        
#         self._asset_out = {
#             "asset": "nep141:zec.omft.near",
#             "amount": decimals_amount
#         }
#         return self

#     def serialize(self):
#         """Serialize the request to the format expected by the solver bus."""
#         if not self._asset_in or not self._asset_out:
#             raise ValueError("Both input and output assets must be specified")
            
#         message = {
#             "defuse_asset_identifier_in": self._asset_in["asset"],
#             "defuse_asset_identifier_out": self._asset_out["asset"],
#             "exact_amount_in": self._asset_in["amount"],
#             "min_deadline_ms": self.min_deadline_ms
#         }
        
#         if self._asset_out["amount"] is not None:
#             message["exact_amount_out"] = self._asset_out["amount"]
            
#         return message

# def fetch_options(request):
#     """Fetches the trading options from the solver bus."""
#     rpc_request = {
#         "id": "dontcare",
#         "jsonrpc": "2.0",
#         "method": "quote",
#         "params": [request.serialize()]
#     }
#     print(f"Sending request to solver bus: {json.dumps(rpc_request, indent=2)}")
#     response = requests.post(INTENTS_RPC_URL, json=rpc_request)
#     response_json = response.json()
#     print(f"Received response from solver bus: {json.dumps(response_json, indent=2)}")
#     return response_json.get("result", [])        

# def select_best_option(options):
#     """Selects the best option from the list of options."""
#     if not options:
#         print("No options available from solver bus")
#         return None
        
#     print(f"Found {len(options)} options from solver bus")
#     best_option = None
#     for i, option in enumerate(options):
#         print(f"Option {i+1}: {json.dumps(option, indent=2)}")
#         if not best_option or float(option.get("amount_out", 0)) > float(best_option.get("amount_out", 0)):
#             best_option = option
            
#     if best_option:
#         print(f"Selected best option: {json.dumps(best_option, indent=2)}")
#     return best_option    

# async def swap_near_to_zec(account, amount):
#     request = IntentRequest()
#     request.set_asset_in("NEAR", float(amount))
#     request.set_asset_out("ZEC") 
#     print(request.serialize())
#     options = fetch_options(request)
#     print(options)

#     if not options:
#         raise ValueError("No swap options available. Try again later or with a different amount.")

#     best_option = select_best_option(options)
#     print(best_option)    

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


async def get_intent_quote():
    body = {
        "id": "dontcare",
        "jsonrpc": "2.0",
        "method": "quote",
        "params": [
            {
                "defuse_asset_identifier_in": "nep141:wrap.near",
                "defuse_asset_identifier_out": "nep141:zec.omft.near",
                "exact_amount_in": "50000000000000000000000",
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

    account = Account(account_id="zcash-sponsor.near", private_key=private_key, rpc_addr=RPC_URL)
    await account.startup()

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

    # Get a quote 
    try:
        quote = await get_intent_quote()
        print(quote)
    except Exception as e:
        print(e)

    # # Swap from NEAR to ZEC
    # try:
    #     await swap_near_to_zec(account, 0.01)
    # except Exception as e:
    #     print(e)



async def main():
    await use_intents()



if __name__ == "__main__":
    asyncio.run(main())
