from hashlib import sha256
from itertools import count
from dataclasses import dataclass
from enum import Enum, auto
from typing import Literal, cast


from enum import IntEnum

import pytest

from web3 import Web3
from web3.middleware.signing import SignAndSendRawMiddlewareBuilder
from eth_account import Account as EthAccount
from ethereum_test_base_types import HexNumber
from ethereum_test_forks import Fork
from ethereum_test_tools import (
    AccessList,
    Account,
    Address,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Bytecode,
    Bytes,
    CodeGasMeasure,
    Conditional,
    Environment,
    EVMCodeType,
    Hash,
    Initcode,
    Requests,
    StateTestFiller,
    Storage,
    Transaction,
    TransactionException,
    add_kzg_version,
    call_return_code,
    compute_create_address,
    Switch,
    Case,
)
from ethereum_test_tools import Macros as Om
from ethereum_test_tools import Opcodes as Op
from ethereum_test_tools.eof.v1 import Container, Section

from .helper import (
    Spec,
)
from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    send_eip7702_transaction,
)

auth_account_start_balance = 0


def get_new_fund_account(ew3: Web3, admin_account):
    new_account = ew3.eth.account.create()
    tx_hash = ew3.eth.send_transaction(
        {
            "from": admin_account.address,
            "to": new_account.address,
            "value": ew3.to_wei(1, "ether"),
        }
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    return new_account

def deploy_contract_using_deploy_code(ew3: Web3, deploy_code: Bytecode) -> str:
    initcode = Initcode(deploy_code=deploy_code)
    tx_hash = ew3.eth.send_transaction(
        {
            "data": bytes(initcode),
        }
    )
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    return cast(str, receipt["contractAddress"])

def assert_account_code_set_to_contract(
    ew3: Web3, account_address: str, contract_address: str
):
    code = ew3.eth.get_code(account_address)  # type: ignore
    assert code.to_0x_hex() == "0xef0100" + contract_address[2:].lower()

# This file contains tests to check the behavior of the set-code transaction on anvil
# Run with:
# anvil --hardfork prague
@pytest.fixture(scope="module")
def ew3(evm_accounts):
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545", request_kwargs={
        "proxies": {
            "http": "",
            "https": "",
        }
    }))
    w3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(evm_accounts))
    w3.eth.default_account = evm_accounts[0].address
    return w3

@pytest.fixture(scope="module")
def evm_accounts(sk):
    EthAccount.enable_unaudited_hdwallet_features()
    return [
        EthAccount.from_key(sk)
    ]

@pytest.fixture(scope="module")
def sk():
    EthAccount.enable_unaudited_hdwallet_features()
    return EthAccount.from_mnemonic("test test test test test test test test test test test junk", account_path="m/44'/60'/0'/0/0").key.hex()


class ReentryAction(IntEnum):
    """Reentry logic action."""

    CALL_PROXY = 0
    MEASURE_VALUES = 1
    MEASURE_VALUES_CONTRACT = 2


@pytest.mark.valid_from("Prague")
def test_pointer_reentry(state_test: StateTestFiller, pre: Alloc):
    """
    Check operations when reenter the pointer again
    TODO: feel free to extend the code checks under given scenarios in switch case.
    """
    env = Environment()
    arg_contract = 0
    arg_action = 32

    storage_b = Storage()
    storage_b.store_next(1, "contract_calls")
    storage_b.store_next(1, "tstore_slot")
    slot_reentry_address = storage_b.store_next(1, "address")

    storage_pointer_b = Storage()
    slot_calls = storage_pointer_b.store_next(2, "pointer_calls")
    slot_tstore = storage_pointer_b.store_next(2, "tstore_slot")

    sender = pre.fund_eoa()
    pointer_b = pre.fund_eoa(amount=1000)
    proxy = pre.deploy_contract(
        code=Op.MSTORE(arg_contract, Op.CALLDATALOAD(arg_contract))
        + Op.MSTORE(arg_action, Op.CALLDATALOAD(arg_action))
        + Op.CALL(gas=800_000, address=pointer_b, args_offset=0, args_size=32 * 2)
    )
    contract_b = pre.deploy_contract(
        balance=100,
        code=Op.MSTORE(arg_contract, Op.CALLDATALOAD(arg_contract))
        + Op.MSTORE(arg_action, Op.CALLDATALOAD(arg_action))
        + Op.SSTORE(slot_calls, Op.ADD(Op.SLOAD(slot_calls), 1))
        + Op.TSTORE(slot_tstore, Op.ADD(Op.TLOAD(slot_tstore), 1))
        + Op.SSTORE(slot_tstore, Op.TLOAD(slot_tstore))
        + Switch(
            cases=[
                Case(
                    condition=Op.EQ(Op.MLOAD(arg_action), ReentryAction.CALL_PROXY),
                    action=Op.MSTORE(arg_action, ReentryAction.MEASURE_VALUES)
                    + Op.CALL(gas=500_000, address=proxy, args_offset=0, args_size=32 * 2)
                    + Op.STOP(),
                ),
                Case(
                    # This code is executed under pointer -> proxy -> pointer context
                    condition=Op.EQ(Op.MLOAD(arg_action), ReentryAction.MEASURE_VALUES),
                    action=Op.SSTORE(storage_pointer_b.store_next(sender, "origin"), Op.ORIGIN())
                    + Op.SSTORE(storage_pointer_b.store_next(pointer_b, "address"), Op.ADDRESS())
                    + Op.SSTORE(
                        storage_pointer_b.store_next(1000, "selfbalance"), Op.SELFBALANCE()
                    )
                    + Op.SSTORE(storage_pointer_b.store_next(proxy, "caller"), Op.CALLER())
                    # now call contract which is pointer dest directly
                    + Op.MSTORE(arg_action, ReentryAction.MEASURE_VALUES_CONTRACT)
                    + Op.CALL(
                        gas=500_000,
                        address=Op.MLOAD(arg_contract),
                        args_offset=0,
                        args_size=32 * 2,
                    ),
                ),
                Case(
                    # This code is executed under
                    # pointer -> proxy -> pointer -> contract
                    # so pointer calling the code of it's dest after reentry to itself
                    condition=Op.EQ(Op.MLOAD(arg_action), ReentryAction.MEASURE_VALUES_CONTRACT),
                    action= Op.SSTORE(storage_b.store_next(sender, "origin"), Op.ORIGIN())
                    + Op.SSTORE(slot_reentry_address, Op.ADDRESS())
                    # + Op.SSTORE(storage_b.store_next(100, "selfbalance"), Op.SELFBALANCE())
                    + Op.SSTORE(storage_b.store_next(1, "const"), 1)
                    # + Op.SSTORE(storage_b.store_next(pointer_b, "caller"), Op.CALLER()),
                ),
            ],
            default_action=None,
        ),
    )

    storage_b[slot_reentry_address] = contract_b

    tx = Transaction(
        to=pointer_b,
        gas_limit=2_000_000,
        data=Hash(contract_b, left_padding=True)
        + Hash(ReentryAction.CALL_PROXY, left_padding=True),
        value=0,
        sender=sender,
        authorization_list=[
            AuthorizationTuple(
                address=contract_b,
                nonce=0,
                signer=pointer_b,
            )
        ],
    )
    post = {
        contract_b: Account(storage=storage_b),
        pointer_b: Account(storage=storage_pointer_b),
    }
    state_test(
        env=env,
        pre=pre,
        post=post,
        tx=tx,
    )


def test_set_code_to_tstore_reentry_contract(
    state_test: StateTestFiller,
    pre: Alloc,
    ew3,
):
    """
    Test the executing a simple TSTORE in a set-code transaction, which also performs a
    re-entry to TLOAD the value.
    """
    auth_signer = pre.fund_eoa(0)
    
    contract_address = compute_create_address(address=ew3.eth.default_account, nonce=ew3.eth.get_transaction_count(ew3.eth.default_account))

    tload_value = 0x1234
    
    # set_code = Conditional(
    #     condition=Op.ISZERO(Op.TLOAD(1)),
    #     if_true=Op.TSTORE(1, tload_value)
    #     + call_opcode(address=contract_address)
    #     + Op.SSTORE(2, tload_value)
    #     + return_opcode(size=32),
    #     if_false=Op.MSTORE(0, Op.TLOAD(1)) 
    #     + Op.SSTORE(2, tload_value) 
    #     + return_opcode(size=32),
    #     evm_code_type=evm_code_type,
    # )
    set_code = Conditional(
        condition=Op.ISZERO(Op.TLOAD(1)),
        if_true=Op.TSTORE(1, tload_value)
        + Op.CALL(address=contract_address)
        + Op.SSTORE(2, tload_value)
        + Op.RETURN(0, 32),
        if_false=Op.RETURN(0, 32),
    )
    set_code_to_address = pre.deploy_contract(set_code)
    
    assert set_code_to_address == contract_address

    tx = Transaction(
        gas_limit=100_000,
        to=auth_signer,
        value=0,
        authorization_list=[
            AuthorizationTuple(
                address=set_code_to_address,
                nonce=0,
                signer=auth_signer,
            ),
        ],
        sender=pre.fund_eoa(),
    )

    state_test(
        env=Environment(),
        pre=pre,
        tx=tx,
        post={
            contract_address: Account(
                storage={
                    2: tload_value
                },
            ),
        },
    )