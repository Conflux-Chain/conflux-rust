"""
CIP-175: cross-space calls (callEVM / staticCallEVM / transferEVM) targeting an
eSpace account with an EIP-7702 delegation must execute the delegated code,
identically to an in-space call.
"""

import pytest
from typing import cast
from web3 import Web3
from ethereum_test_tools import Initcode, Opcodes as Op

from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    send_eip7702_transaction,
)

COUNTER_SLOT = 1


def get_new_fund_account(ew3: Web3):
    new_account = ew3.eth.account.create()
    tx_hash = ew3.eth.send_transaction(
        {
            "to": new_account.address,
            "value": ew3.to_wei(1, "ether"),
        }
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    return new_account


def deploy_contract_using_deploy_code(ew3: Web3, deploy_code) -> str:
    initcode = Initcode(deploy_code=deploy_code)
    tx_hash = ew3.eth.send_transaction(
        {
            "data": bytes(initcode),
        }
    )
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    return cast(str, receipt["contractAddress"])


def delegate_to(ew3: Web3, contract_address: str):
    """Create a fresh eSpace EOA delegated to `contract_address`."""
    authority = get_new_fund_account(ew3)
    sender = get_new_fund_account(ew3)
    tx_hash = send_eip7702_transaction(
        ew3,
        sender,
        {
            "authorizationList": [
                sign_authorization(
                    contract_address=contract_address,
                    chain_id=ew3.eth.chain_id,
                    nonce=0,
                    private_key=authority.key.to_0x_hex(),
                )
            ],
            "to": ew3.eth.account.create().address,
        },
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    code = ew3.eth.get_code(authority.address)
    assert code.to_0x_hex() == "0xef0100" + contract_address[2:].lower()
    return authority


@pytest.fixture(scope="module")
def counter_contract_address(ew3: Web3) -> str:
    # Increments a counter in the caller-context storage on every call.
    code = Op.SSTORE(COUNTER_SLOT, Op.ADD(Op.SLOAD(COUNTER_SLOT), 1)) + Op.STOP
    return deploy_contract_using_deploy_code(ew3, code)


@pytest.fixture(scope="module")
def reader_contract_address(ew3: Web3) -> str:
    # Returns the constant 42 (static-call friendly: no state writes).
    code = Op.MSTORE(0, 42) + Op.RETURN(0, 32)
    return deploy_contract_using_deploy_code(ew3, code)


def counter_value(ew3: Web3, address: str) -> int:
    return int.from_bytes(ew3.eth.get_storage_at(address, COUNTER_SLOT), "big")


def test_call_evm_to_delegated_account(
    cw3, ew3: Web3, internal_contracts, counter_contract_address
):
    authority = delegate_to(ew3, counter_contract_address)
    assert counter_value(ew3, authority.address) == 0

    cross_space_call = internal_contracts["CrossSpaceCall"]
    tx_hash = cross_space_call.functions.callEVM(authority.address, b"").transact()
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)
    assert receipt["outcomeStatus"] == 0

    # The delegated code ran in the authority's context.
    assert counter_value(ew3, authority.address) == 1
    assert counter_value(ew3, counter_contract_address) == 0


def test_static_call_evm_to_delegated_account(
    ew3: Web3, internal_contracts, reader_contract_address
):
    authority = delegate_to(ew3, reader_contract_address)

    cross_space_call = internal_contracts["CrossSpaceCall"]
    output = cross_space_call.functions.staticCallEVM(
        authority.address, b""
    ).call()
    assert int.from_bytes(output, "big") == 42


def test_transfer_evm_to_delegated_account(
    cw3, ew3: Web3, internal_contracts, counter_contract_address
):
    authority = delegate_to(ew3, counter_contract_address)
    balance_before = ew3.eth.get_balance(authority.address)
    counter_before = counter_value(ew3, authority.address)

    cross_space_call = internal_contracts["CrossSpaceCall"]
    tx_hash = cross_space_call.functions.transferEVM(authority.address).transact(
        {"value": 10**18}
    )
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)
    assert receipt["outcomeStatus"] == 0

    # Value arrives and the delegated code runs, as for an in-space transfer.
    assert ew3.eth.get_balance(authority.address) == balance_before + 10**18
    assert counter_value(ew3, authority.address) == counter_before + 1
