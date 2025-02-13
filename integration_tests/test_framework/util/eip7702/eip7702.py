import json
import subprocess
from pydantic import BaseModel, Field, ConfigDict
from pathlib import Path
from typing import TypedDict

class Authorization(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    chainId: int = Field(alias='chain_id')
    nonce: int
    contractAddress: str = Field(alias='contract_address')
    r: str
    s: str
    v: int
    yParity: int

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
    ]
    
    args = {
        'transaction': tx_dict,
        'privateKey': private_key
    }
    
    result = _run_node_script('signTransaction', args)
    if isinstance(result, dict):
        return result['signedTransaction']
    return result
