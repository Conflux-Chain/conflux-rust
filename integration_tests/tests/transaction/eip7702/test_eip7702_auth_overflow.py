import pytest
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.exceptions import Web3RPCError

from ethereum_test_tools import (
    Initcode,
    Opcodes as Op,
    Storage,
    Bytecode,
    Macros as Om,
)
from web3.types import RPCEndpoint

MAX_AUTH_CHAIN_ID = 2 ** 256 - 1
MAX_AUTH_NONCE = 2 ** 64 - 1

@pytest.fixture(scope="module")
def contract_address(ew3: Web3) -> str:
    return ew3.eth.account.create().address


def get_new_fund_account(ew3: Web3) -> LocalAccount:
    new_account = ew3.eth.account.create()
    tx_hash = ew3.eth.send_transaction(
        {
            "to": new_account.address,
            "value": ew3.to_wei(1, "ether"),
        }
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    return new_account

@pytest.mark.parametrize("auth_chain_id, auth_nonce, should_overflow", [
    (MAX_AUTH_CHAIN_ID, MAX_AUTH_NONCE, False),
    (MAX_AUTH_CHAIN_ID+1, MAX_AUTH_NONCE, True),
    (MAX_AUTH_CHAIN_ID, MAX_AUTH_NONCE+1, True),
])
def test_auth_overflow_chain_id(ew3: Web3, contract_address: str, auth_chain_id: int, auth_nonce: int, should_overflow: bool):
    acct = get_new_fund_account(ew3)
    nonce = ew3.eth.get_transaction_count(acct.address)
    auth = ew3.eth.account.sign_authorization({
        "chainId": auth_chain_id,
        "address": contract_address,
        "nonce": auth_nonce,
    }, acct.key)
    raw_tx = acct.sign_transaction({
        "to": ew3.eth.account.create().address,
        "chainId": ew3.eth.chain_id,
        "nonce": nonce,
        "maxFeePerGas": ew3.to_wei(1, "gwei"),
        "maxPriorityFeePerGas": ew3.to_wei(1, "gwei"),
        "gas": 200000,
        "authorizationList": [auth]
    })
    if should_overflow:
        with pytest.raises(Web3RPCError) as e:
            ew3.eth.send_raw_transaction(raw_tx.raw_transaction)
        assert e.value.message == "{'code': -32602, 'message': 'failed to decode signed transaction'}"
    else:
        tx_hash = ew3.eth.send_raw_transaction(raw_tx.raw_transaction)
        ew3.eth.wait_for_transaction_receipt(tx_hash)