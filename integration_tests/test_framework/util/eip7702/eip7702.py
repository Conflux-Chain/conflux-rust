import json
import subprocess
from pathlib import Path
from typing import TypedDict
from typing_extensions import NotRequired
from web3 import Web3
from hexbytes import HexBytes
from eth_account import Account
from eth_account.datastructures import SignedSetCodeAuthorization
from eth_account.signers.local import LocalAccount

class EIP7702TransactionParams(TypedDict):
    authorizationList: list[SignedSetCodeAuthorization]
    chainId: NotRequired[int]
    gas: NotRequired[int]
    nonce: NotRequired[int]
    to: NotRequired[str]
    value: NotRequired[int]
    maxFeePerGas: NotRequired[int]
    maxPriorityFeePerGas: NotRequired[int]
    # accessList: list[AccessList]
    data: NotRequired[str]

class EIP7702Transaction(TypedDict):
    authorizationList: list[SignedSetCodeAuthorization]
    chainId: int
    gas: int
    nonce: int
    to: str
    value: int
    maxFeePerGas: int
    maxPriorityFeePerGas: int
    # accessList: list[AccessList]
    data: str

def _run_node_script(command: str, args: dict) -> dict:
    script_path = Path(__file__).parent / 'viem_scripts' / 'eip7702.js'
    print(f"Running command: node {script_path} {command} {json.dumps(args)}")
    result = subprocess.run(
        ['node', str(script_path), command, json.dumps(args)],
        capture_output=True,
        text=True,
        check=True
    )
    return json.loads(result.stdout)

def sign_authorization(contract_address: str, chain_id: int, nonce: int, private_key: str) -> SignedSetCodeAuthorization:
    """
    Sign an EIP-7702 authorization
    
    Args:
        contract_address: The contract address to authorize
        chain_id: The chain ID
        nonce: The nonce
        private_key: The private key to sign with
        
    Returns:
        An Authorization object containing the signature
    """
    return Account.sign_authorization({
        "chainId": chain_id,
        "address": contract_address,
        "nonce": nonce
    }, private_key)

def sign_eip7702_transaction(transaction: EIP7702Transaction, private_key: str) -> str:
    """
    Sign an EIP-7702 transaction using viem
    
    Args:
        transaction: The transaction to sign
        private_key: The private key to sign with
        
    Returns:
        The signed transaction as a hex string
    """
    return Account.sign_transaction(transaction, private_key).raw_transaction

def construrct_eip7702_transaction(ew3: Web3, sender: str, transaction: EIP7702TransactionParams) -> EIP7702Transaction:
    assert "authorizationList" in transaction, "authorizationList is required"
    if "to" not in transaction:
        transaction["to"] = None
    if "data" not in transaction:
        transaction["data"] = "0x"
    if "value" not in transaction:
        transaction["value"] = 0
    if "chainId" not in transaction:
        transaction["chainId"] = ew3.eth.chain_id
    if "nonce" not in transaction:
        transaction["nonce"] = ew3.eth.get_transaction_count(sender)
    if "gas" not in transaction:
        transaction["gas"] = estimate_gas(ew3, sender, transaction)
    if "maxPriorityFeePerGas" not in transaction:
        transaction["maxPriorityFeePerGas"] = ew3.eth.max_priority_fee
    if "maxFeePerGas" not in transaction:
        transaction["maxFeePerGas"] = ew3.eth.get_block("latest")["baseFeePerGas"] * 2 + transaction["maxPriorityFeePerGas"]
    return transaction
    

def estimate_gas(ew3: Web3, from_address: str, transaction: EIP7702Transaction) -> int:
    estimate_params = {
        "from": from_address,
        "to": transaction["to"],
        "value": hex(transaction["value"]),
        "data": transaction["data"],
        "authorizationList": [
            {
                "chainId": hex(authorization.chain_id),
                "nonce": hex(authorization.nonce),
                "address": f"0x{authorization.address.hex()}",
                "r": hex(authorization.r),
                "s": hex(authorization.s),
                "yParity": hex(authorization.y_parity)
            } for authorization in transaction["authorizationList"]
        ]
    }
    return int(ew3.manager.request_blocking("eth_estimateGas", [estimate_params]), 16)

def sign_eip7702_transaction_with_default_fields(ew3: Web3, sender: LocalAccount, transaction: EIP7702TransactionParams) -> HexBytes:
    return sign_eip7702_transaction(construrct_eip7702_transaction(ew3, sender.address, transaction), sender.key.to_0x_hex())

# returns tx hash
def send_eip7702_transaction(ew3: Web3, sender: LocalAccount, transaction: EIP7702TransactionParams):
    tx_raw = sign_eip7702_transaction_with_default_fields(ew3, sender, transaction)
    return ew3.eth.send_raw_transaction(tx_raw)