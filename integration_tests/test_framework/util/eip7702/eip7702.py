import json
import subprocess
from pydantic import BaseModel, Field, ConfigDict
from pathlib import Path
from typing import TypedDict
from typing_extensions import NotRequired
from web3 import Web3
from hexbytes import HexBytes
from eth_account.signers.local import LocalAccount

class Authorization(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    chainId: int = Field(alias='chain_id')
    nonce: int
    contractAddress: str = Field(alias='contract_address')
    r: str
    s: str
    v: int
    yParity: int

class EIP7702TransactionParams(TypedDict):
    authorizationList: list[Authorization]
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
    authorizationList: list[Authorization]
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

def sign_authorization(contract_address: str, chain_id: int, nonce: int, private_key: str) -> Authorization:
    """
    Sign an EIP-7702 authorization using viem
    
    Args:
        contract_address: The contract address to authorize
        chain_id: The chain ID
        nonce: The nonce
        private_key: The private key to sign with
        
    Returns:
        An Authorization object containing the signature
    """
    args = {
        'contractAddress': contract_address,
        'chainId': chain_id,
        'nonce': nonce,
        'privateKey': private_key
    }
    
    result = _run_node_script('signAuthorization', args)
    return Authorization(
        chain_id=chain_id,
        nonce=nonce,
        contract_address=contract_address,
        r=result['r'],
        s=result['s'],
        v=result['v'],
        yParity=result['yParity']
    )

def sign_eip7702_transaction(transaction: EIP7702Transaction, private_key: str) -> str:
    """
    Sign an EIP-7702 transaction using viem
    
    Args:
        transaction: The transaction to sign
        private_key: The private key to sign with
        
    Returns:
        The signed transaction as a hex string
    """
    # Convert Authorization objects to dict with camelCase keys
    tx_dict = dict(transaction)
    tx_dict['authorizationList'] = [
        {
            'chainId': auth.chainId,
            'nonce': auth.nonce,
            'contractAddress': auth.contractAddress,
            'r': auth.r,
            's': auth.s,
            'v': auth.v,
            'yParity': auth.yParity
        }
        for auth in transaction['authorizationList']
    ] if transaction['authorizationList'] is not None else None
    
    args = {
        'transaction': tx_dict,
        'privateKey': private_key
    }
    
    result = _run_node_script('signTransaction', args)
    if isinstance(result, dict):
        return result['signedTransaction']
    return HexBytes(result)

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
                "chainId": hex(authorization.chainId),
                "nonce": hex(authorization.nonce),
                "address": authorization.contractAddress,
                "r": authorization.r,
                "s": authorization.s,
                "yParity": hex(authorization.yParity)
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