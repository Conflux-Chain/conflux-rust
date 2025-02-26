from hashlib import sha256
from itertools import count
from dataclasses import dataclass
from enum import Enum, auto
from typing import Literal

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
)
from ethereum_test_tools import Macros as Om
from ethereum_test_tools import Opcodes as Op
from ethereum_test_tools.eof.v1 import Container, Section

from integration_tests.test_framework.util.adapter import AllocMock

auth_account_start_balance = 0

class AddressType(Enum):
    """
    Different types of addresses used to specify the type of authority that signs an authorization,
    and the type of address to which the authority authorizes to set the code to.
    """

    EMPTY_ACCOUNT = auto()
    EOA = auto()
    EOA_WITH_SET_CODE = auto()
    CONTRACT = auto()

@dataclass(frozen=True)
class Spec:
    """
    Parameters from the EIP-7702 specifications as defined at
    https://eips.ethereum.org/EIPS/eip-7702.
    """

    SET_CODE_TX_TYPE = 0x04
    MAGIC = 0x05
    PER_AUTH_BASE_COST = 12_500
    PER_EMPTY_ACCOUNT_COST = 25_000
    DELEGATION_DESIGNATION = Bytes("ef0100")
    RESET_DELEGATION_ADDRESS = Address(0)

    MAX_AUTH_CHAIN_ID = 2**256 - 1
    MAX_NONCE = 2**64 - 1

    @staticmethod
    def delegation_designation(address: Address) -> Bytes:
        """Return delegation designation for the given address."""
        return Bytes(Spec.DELEGATION_DESIGNATION + bytes(address))

# This file contains tests to check the behavior of the set-code transaction on anvil
# Run with:
# anvil --hardfork prague
@pytest.fixture(scope="module")
def ew3(evm_accounts):
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    w3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(evm_accounts))
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



@pytest.mark.parametrize(
    "external_sendall_recipient",
    [
        False, 
        True
    ],
)
@pytest.mark.parametrize(
    "balance",
    [
        0,
        1
    ],
)
@pytest.mark.parametrize("call_set_code_first", [
    False, 
    True
])
@pytest.mark.parametrize(
    "create_opcode", [
        Op.CREATE, 
        Op.CREATE2
    ]
)  # EOF code does not support SELFDESTRUCT
def test_set_code_to_self_destructing_account_deployed_in_same_tx(
    state_test: StateTestFiller,
    pre: Alloc,
    create_opcode: Op,
    call_set_code_first: bool,
    external_sendall_recipient: bool,
    balance: int,
):
    """
    Test setting the code of an account to an account that contains the SELFDESTRUCT opcode and
    was deployed in the same transaction, and test calling the set-code address and the deployed
    in both sequence orders.
    """
    # Fund the auth_signer account with the specified balance
    auth_signer = pre.fund_eoa(balance)
    if external_sendall_recipient:
        # Create a separate recipient account with 0 balance if external recipient is enabled
        recipient = pre.fund_eoa(0)
    else:
        # Otherwise use auth_signer as the recipient
        recipient = auth_signer

    # Storage slot to track successful execution
    success_slot = 1

    # Create contract code that stores success and self-destructs, sending funds to recipient
    deployed_code = Op.SSTORE(success_slot, 1) + Op.SELFDESTRUCT(recipient)
    initcode = Initcode(deploy_code=deployed_code)

    # Storage slots for tracking addresses and call results
    deployed_contract_address_slot = 1
    signer_call_return_code_slot = 2
    deployed_contract_call_return_code_slot = 3

    salt = 0
    call_opcode = Op.CALL

    # Contract creator code that:
    # 1. Copies calldata to memory
    # 2. Creates new contract using specified create opcode
    # 3. Stores the new contract's address
    contract_creator_code: Bytecode = Op.CALLDATACOPY(0, 0, Op.CALLDATASIZE) + Op.SSTORE(
        deployed_contract_address_slot,
        create_opcode(offset=0, salt=salt, size=Op.CALLDATASIZE),
    )
    if call_set_code_first:
        # If calling set-code first:
        # 1. Call auth_signer and store result
        # 2. Call deployed contract and store result
        contract_creator_code += Op.SSTORE(
            signer_call_return_code_slot, call_opcode(address=auth_signer)
        ) + Op.SSTORE(
            deployed_contract_call_return_code_slot,
            call_opcode(address=Op.SLOAD(deployed_contract_address_slot)),
        )
    else:
        # If calling deployed contract first:
        # 1. Call deployed contract and store result
        # 2. Call auth_signer and store result
        contract_creator_code += Op.SSTORE(
            deployed_contract_call_return_code_slot,
            call_opcode(address=Op.SLOAD(deployed_contract_address_slot)),
        ) + Op.SSTORE(signer_call_return_code_slot, call_opcode(address=auth_signer))

    # Add STOP opcode at the end
    contract_creator_code += Op.STOP

    # Deploy the contract creator contract
    contract_creator_address = pre.deploy_contract(contract_creator_code)

    # Compute the address where the new contract will be deployed
    deployed_contract_address = compute_create_address(
        address=contract_creator_address,
        nonce=1,
        salt=salt,
        initcode=initcode,
        opcode=create_opcode,
    )

    tx = Transaction(
        gas_limit=10_000_000,
        to=contract_creator_address,
        value=0,
        data=initcode,
        authorization_list=[
            AuthorizationTuple(
                address=deployed_contract_address,
                nonce=0,
                signer=auth_signer,
            ),
        ],
        sender=pre.fund_eoa(),
    )

    post = {
        deployed_contract_address: Account.NONEXISTENT,
        auth_signer: Account(
            nonce=1,
            code=Spec.delegation_designation(deployed_contract_address),
            storage={success_slot: 1},
            balance=balance if not external_sendall_recipient else 0,
        ),
        contract_creator_address: Account(
            storage={
                deployed_contract_address_slot: deployed_contract_address,
                signer_call_return_code_slot: 1,
                deployed_contract_call_return_code_slot: 1,
            }
        ),
    }

    if external_sendall_recipient and balance > 0:
        post[recipient] = Account(balance=balance)

    state_test(
        env=Environment(),
        pre=pre,
        tx=tx,
        post=post,
    )
