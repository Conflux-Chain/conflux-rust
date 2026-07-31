"""
Before CIP-175 activation, a cross-space call to an eSpace account with an
EIP-7702 delegation keeps the legacy behavior: the raw delegation designator
is loaded as code and fails on the invalid 0xef opcode.
"""

import pytest
from typing import cast
from web3 import Web3
from ethereum_test_tools import Initcode, Opcodes as Op

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    send_eip7702_transaction,
)

MIN_NATIVE_BASE_PRICE = 10000
EVM_CHAIN_ID = 11
COUNTER_SLOT = 1


@pytest.fixture(scope="module")
def framework_class():
    class CIP175PreActivationTestEnv(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["evm_chain_id"] = str(EVM_CHAIN_ID)
            self.conf_parameters["min_native_base_price"] = MIN_NATIVE_BASE_PRICE
            self.conf_parameters["eoa_code_transition_height"] = 1
            self.conf_parameters["align_evm_transition_height"] = 1
            self.conf_parameters["cip175_transition_height"] = 10**9
            self.conf_parameters["evm_transaction_block_ratio"] = str(1)
            self.conf_parameters["public_evm_rpc_apis"] = '"all"'
            self.conf_parameters["executive_trace"] = "true"

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])

    return CIP175PreActivationTestEnv


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


def counter_value(ew3: Web3, address: str) -> int:
    return int.from_bytes(ew3.eth.get_storage_at(address, COUNTER_SLOT), "big")


def test_call_evm_to_delegated_account_before_activation(
    cw3, ew3: Web3, internal_contracts
):
    code = Op.SSTORE(COUNTER_SLOT, Op.ADD(Op.SLOAD(COUNTER_SLOT), 1)) + Op.STOP
    counter_contract_address = deploy_contract_using_deploy_code(ew3, code)
    authority = delegate_to(ew3, counter_contract_address)

    cross_space_call = internal_contracts["CrossSpaceCall"]
    # Provide gas and storageLimit explicitly: the call is expected to fail,
    # so gas estimation would raise before sending the transaction.
    tx_hash = cross_space_call.functions.callEVM(authority.address, b"").transact(
        {"gas": 3_000_000, "storageLimit": 0, "gasPrice": MIN_NATIVE_BASE_PRICE}
    )

    # The designator bytes are executed as code and hit the invalid 0xef
    # opcode (BadInstruction), so the call fails and the delegated code
    # never runs. conflux-web3 raises on a failed transaction.
    with pytest.raises(RuntimeError, match="BadInstruction"):
        cw3.cfx.wait_for_transaction_receipt(tx_hash)
    assert counter_value(ew3, authority.address) == 0
