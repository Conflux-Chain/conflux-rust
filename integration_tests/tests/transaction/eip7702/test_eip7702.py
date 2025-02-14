import pytest
from typing import Type
from integration_tests.test_framework.util import load_contract_metadata
from web3 import Web3
from web3.contract import Contract
from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    sign_eip7702_transaction,
    Authorization,
    EIP7702Transaction
)

@pytest.fixture(scope="module")
def erc20_factory(ew3: Web3) -> Type[Contract]:
    metadata = load_contract_metadata("MyToken")  # ERC20 contract
    contract_factory = ew3.eth.contract(
        bytecode=metadata["bytecode"],
        abi=metadata["abi"],
    )
    return contract_factory

@pytest.fixture(scope="module")
def erc20_contract(ew3: Web3, erc20_factory: Type[Contract], evm_accounts) -> Contract:
    tx_hash = erc20_factory.constructor(
        evm_accounts[0].address
    ).transact()
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    return erc20_factory(receipt["contractAddress"])

# use self as erc20 contract
# and mint self 10**18
def test_eip7702(ew3: Web3, erc20_factory: Type[Contract], erc20_contract: Contract, evm_accounts, network):
    
    account = evm_accounts[0]
    
    chain_id = ew3.eth.chain_id
    authorization = sign_authorization(
        contract_address=erc20_contract.address,
        chain_id=chain_id,
        nonce=ew3.eth.get_transaction_count(account.address) + 1,
        private_key=account.key.to_0x_hex(),
    )
    
    transaction: EIP7702Transaction = {
        "authorizationList": [authorization],
        "chainId": chain_id,
        "gas": 1000000,
        "nonce": ew3.eth.get_transaction_count(account.address),
        "to": "0x0000000000000000000000000000000000000000",
        "value": 0,
        "maxFeePerGas": 1000000000,
        "maxPriorityFeePerGas": 100000000,
        "data": "0x"
    }
    
    tx_raw = sign_eip7702_transaction(transaction, account.key.to_0x_hex())
    tx_hash = ew3.eth.send_raw_transaction(tx_raw)
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash, timeout=10, poll_latency=1)
    
    assert receipt["status"] == 1
    
    self_contract = erc20_factory(evm_accounts[0].address)
    
    code = ew3.eth.get_code(self_contract.address)
    assert code.to_0x_hex() == "0xef0100" + erc20_contract.address[2:].lower()
    
    assert self_contract.functions.balanceOf(account.address).call() == 0
    
