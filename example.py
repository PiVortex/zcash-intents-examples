from py_near.providers import JsonProvider
from py_near.account import Account
from py_near.dapps.core import NEAR
from dotenv import load_dotenv
from typing import TypedDict, List, Dict, Union, Optional, Any
import near_api
import os
import nacl.signing
import base64
import random
import base58
import asyncio
import requests
import json
import hashlib
from borsh_construct import U32
import secrets
import time
from datetime import datetime

RPC_URL = "https://free.rpc.fastnear.com"
INTENTS_RPC_URL = "https://solver-relay-v2.chaindefuser.com/rpc"
GAS = 300 * 10 ** 12
    

class BinarySerializer:
    def __init__(self, schema):
        self.array = bytearray()
        self.schema = schema
        self.offset = 0  # Add this for deserialize_field

    def read_bytes(self, n):
        assert n + self.offset <= len(
            self.array
        ), f'n: {n} offset: {self.offset}, length: {len(self.array)}'
        ret = self.array[self.offset:self.offset + n]
        self.offset += n
        return ret

    def serialize_num(self, value, n_bytes):
        assert value >= 0
        for i in range(n_bytes):
            self.array.append(value & 255)
            value //= 256
        assert value == 0

    def deserialize_num(self, n_bytes):
        value = 0
        bytes_ = self.read_bytes(n_bytes)
        for b in bytes_[::-1]:
            value = value * 256 + b
        return value

    def serialize_field(self, value, fieldType):
        if type(fieldType) == tuple:
            if len(fieldType) == 0:
                pass
            else:
                assert len(value) == len(fieldType)
                for (v, t) in zip(value, fieldType):
                    self.serialize_field(v, t)
        elif type(fieldType) == str:
            if fieldType == 'bool':
                assert isinstance(value, bool), str(type(value))
                self.serialize_num(int(value), 1)
            elif fieldType[0] == 'u':
                self.serialize_num(value, int(fieldType[1:]) // 8)
            elif fieldType == 'string':
                b = value.encode('utf8')
                self.serialize_num(len(b), 4)
                self.array += b
            else:
                assert False, fieldType
        elif type(fieldType) == list:
            assert len(fieldType) == 1
            if type(fieldType[0]) == int:
                assert type(value) == bytes
                assert len(value) == fieldType[0], "len(%s) = %s != %s" % (
                    value, len(value), fieldType[0])
                self.array += bytearray(value)
            else:
                self.serialize_num(len(value), 4)
                for el in value:
                    self.serialize_field(el, fieldType[0])
        elif type(fieldType) == dict:
            assert fieldType['kind'] == 'option'
            if value is None:
                self.serialize_num(0, 1)
            else:
                self.serialize_num(1, 1)
                self.serialize_field(value, fieldType['type'])
        elif type(fieldType) == type:
            assert type(value) == fieldType, "%s != type(%s)" % (fieldType,
                                                                 value)
            self.serialize_struct(value)
        else:
            assert False, type(fieldType)

    def serialize_struct(self, obj):
        structSchema = self.schema[type(obj)]
        if structSchema['kind'] == 'struct':
            for fieldName, fieldType in structSchema['fields']:
                self.serialize_field(getattr(obj, fieldName), fieldType)
        elif structSchema['kind'] == 'enum':
            name = getattr(obj, structSchema['field'])
            for idx, (fieldName,
                      fieldType) in enumerate(structSchema['values']):
                if fieldName == name:
                    self.serialize_num(idx, 1)
                    self.serialize_field(getattr(obj, fieldName), fieldType)
                    break
            else:
                assert False, name
        else:
            assert False, structSchema

    def serialize(self, obj):
        self.serialize_struct(obj)
        return bytes(self.array)

class Payload:
    def __init__(
        self, message: str, nonce: Union[bytes, str, List[int]], recipient: str, callback_url: Optional[str] = None
    ):
        self.message = message
        self.nonce = convert_nonce(nonce)
        self.recipient = recipient
        self.callbackUrl = callback_url

PAYLOAD_SCHEMA: list[list[Any]] = [
    [
        Payload,
        {
            "kind": "struct",
            "fields": [
                ["message", "string"],
                ["nonce", [32]],
                ["recipient", "string"],
                [
                    "callbackUrl",
                    {
                        "kind": "option",
                        "type": "string",
                    },
                ],
            ],
        },
    ]
]

def base64_to_uint8array(base64_string):
    binary_data = base64.b64decode(base64_string)
    return list(binary_data)

def convert_nonce(value: Union[str, bytes, list[int]]):
    """Converts a given value to a 32-byte nonce."""
    if isinstance(value, bytes):
        if len(value) > 32:
            raise ValueError("Invalid nonce length")
        if len(value) < 32:
            value = value.rjust(32, b"0")
        return value
    elif isinstance(value, str):
        nonce_bytes = value.encode("utf-8")
        if len(nonce_bytes) > 32:
            raise ValueError("Invalid nonce length")
        if len(nonce_bytes) < 32:
            nonce_bytes = nonce_bytes.rjust(32, b"0")
        return nonce_bytes
    elif isinstance(value, list):
        if len(value) != 32:
            raise ValueError("Invalid nonce length")
        return bytes(value)
    else:
        raise ValueError("Invalid nonce format")

async def generate_nonce():
    random_array = secrets.token_bytes(32)
    return base64.b64encode(random_array).decode('utf-8')

async def get_quote(amount_in: float, near_to_zcash: bool = True):
    """
    Get a quote for swapping between NEAR and ZEC in either direction
    
    Args:
        amount_in (float): Amount to swap (in NEAR if near_to_zcash=True, in ZEC if near_to_zcash=False)
        near_to_zcash (bool): Direction of swap. True for NEAR->ZEC, False for ZEC->NEAR
    Returns:
        dict: Quote information
    """
    # Convert amount to proper decimals (NEAR has 24, ZEC has 8)
    amount_in_smallest = str(int(amount_in * (10 ** 24 if near_to_zcash else 10 ** 8)))
    
    # Set asset identifiers based on direction
    asset_in = "nep141:wrap.near" if near_to_zcash else "nep141:zec.omft.near"
    asset_out = "nep141:zec.omft.near" if near_to_zcash else "nep141:wrap.near"
    
    body = {
        "id": "dontcare",
        "jsonrpc": "2.0",
        "method": "quote",
        "params": [
            {
                "defuse_asset_identifier_in": asset_in,
                "defuse_asset_identifier_out": asset_out,
                "exact_amount_in": amount_in_smallest,
            }
        ]
    }

    response = requests.post(
        INTENTS_RPC_URL,
        json=body,
        headers={
            "Content-Type": "application/json"
        }
    )

    if not response.ok:
        raise Exception(
            f"Request failed {response.status_code} {response.reason} - {response.text}"
        )

    json_response = response.json()
    result = json_response.get("result")

    if not result or len(result) == 0:
        raise Exception("No quote available")
        
    return result[0]

async def execute_intent(account_id: str, signer, quote: dict):
    """
    Execute an intent with a given quote
    
    Args:
        account_id (str): The account executing the intent
        signer: The signer object for signing the intent
        quote (dict): The quote to execute
    Returns:
        dict: Response from the intent execution
    """
    standard = "nep413"
    recipient = "intents.near"

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
    message_str = json.dumps(message)
    
    nonce = await generate_nonce()
    nonce_uint8array = base64_to_uint8array(nonce)

    # Create payload and serialize it according to NEP-413
    payload = Payload(message_str, nonce_uint8array, recipient, None)
    borsh_payload = BinarySerializer(dict(PAYLOAD_SCHEMA)).serialize(payload)
    
    # Add the NEP-413 prefix
    base_int = 2 ** 31 + 413
    base_int_serialized = U32.build(base_int)
    combined_data = base_int_serialized + borsh_payload
    
    # Hash the data that needs to be signed
    hash_to_sign = hashlib.sha256(combined_data).digest()
    
    # Sign the hash
    signature_bytes = signer.sign(hash_to_sign)
    signature = 'ed25519:' + base58.b58encode(signature_bytes).decode('utf-8')
    public_key = 'ed25519:' + base58.b58encode(signer.public_key).decode('utf-8')

    # Create the payload
    payload = {
        "message": message_str,
        "nonce": nonce,
        "recipient": recipient
    }

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
    
    # Send the intent to the RPC endpoint
    response = requests.post(
        INTENTS_RPC_URL,
        json=intent,
        headers={
            "Content-Type": "application/json"
        }
    )

    if not response.ok:
        raise Exception(
            f"Request failed {response.status_code} {response.reason} - {response.text}"
        )

    json_response = response.json()
    result = json_response.get("result")

    return result

async def publish_intent(account_id, signer):
    try:
        quote = await get_quote(0.01)
        print("Actual amount out: ", float(quote['amount_out']) / 10 ** 8)
        
        result = await execute_intent(account_id, signer, quote)
        return result
    except Exception as e:
        print(f"Failed to execute intent: {e}")
        return None

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

async def main():
    load_dotenv()

    # Get private key for creator account from environment variable
    private_key = os.getenv('CREATOR_PRIVATE_KEY')
    public_key = os.getenv('CREATOR_PUBLIC_KEY')
    if not private_key:
        raise ValueError("CREATOR_PRIVATE_KEY not found in .env file")
    if not public_key:
        raise ValueError("CREATOR_PUBLIC_KEY not found in .env file")

    account_id = "zcash-sponsor.near"
    
    # Create account object for deposit
    account = Account(account_id=account_id, private_key=private_key, rpc_addr=RPC_URL)
    await account.startup()

    try:
        # Create signer for intent execution
        key_pair = near_api.signer.KeyPair(private_key)
        signer = near_api.signer.Signer(account_id, key_pair)

        # Specify swap direction
        near_to_zcash = False  # Change this to True for NEAR->ZEC, False for ZEC->NEAR
        
        # Set amount based on direction (0.01 NEAR or 0.001 ZEC as examples)
        amount = 0.01 if near_to_zcash else 0.001
        
        # Get quote with specified direction
        quote = await get_quote(amount, near_to_zcash)
        
        # Print appropriate message based on direction
        if near_to_zcash:
            print(f"\nSwapping NEAR to ZEC:")
            print(f"Input: {float(quote['amount_in'])/10**24:.6f} NEAR")
            print(f"Output: {float(quote['amount_out'])/10**8:.8f} ZEC")
        else:
            print(f"\nSwapping ZEC to NEAR:")
            print(f"Input: {float(quote['amount_in'])/10**8:.8f} ZEC")
            print(f"Output: {float(quote['amount_out'])/10**24:.6f} NEAR")
        
        # Check quote expiration
        # Convert ISO 8601 timestamp to Unix timestamp
        expiration_time = int(datetime.strptime(quote["expiration_time"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp())
        current_time = int(time.time())
        time_left = expiration_time - current_time
        print(f"Quote valid for: {time_left} seconds ({time_left/60:.2f} minutes)")

        if near_to_zcash:
            # Deposit 0.01 NEAR
            print("Depositing 0.01 NEAR...")
            await deposit_near(account, amount)
            print("Deposit successful")
        else:
            # TODO: Deposit ZEC

        # Execute the intent with the quote
        result = await execute_intent(account_id, signer, quote)
        print("Intent execution result:", result)
    except Exception as e:
        print(f"Failed to execute intent: {e}")


if __name__ == "__main__":
    asyncio.run(main())
