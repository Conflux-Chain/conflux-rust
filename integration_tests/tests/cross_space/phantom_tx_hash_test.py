from typing import Type
import pytest

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from eth_utils import decode_hex


@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(ConfluxTestFramework):

        def set_test_params(self):
            self.num_nodes = 1
            self.core_secrets.append(decode_hex("46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495a").hex())

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])

    return DefaultFramework


@pytest.fixture(scope="module")
def evm_contract(network: ConfluxTestFramework):
    return network.deploy_evm_contract("CrossSpaceEventTestEVMSide")


def test_withdrawFromMapped_phantom_tx_hash_unique(cw3, ew3, core_accounts, evm_accounts, evm_contract, internal_contracts):
    # use diff sender to withdrawFromMapped, phantom tx hash in evm space should be different
    transfer_call(internal_contracts, cw3, core_accounts[0].address.mapped_evm_space_address)
    transfer_call(internal_contracts, cw3, core_accounts[1].address.mapped_evm_space_address)

    cross_space_call = internal_contracts["CrossSpaceCall"]
    tx_hash1 = cross_space_call.functions.withdrawFromMapped(1).transact({"from": core_accounts[0].address})
    receipt1 = cw3.cfx.wait_for_transaction_receipt(tx_hash1)
    assert receipt1["outcomeStatus"] == 0

    block1 = ew3.eth.get_block(receipt1["blockHash"])
    phantom_txs_1 = block1["transactions"]
    assert len(phantom_txs_1) == 1
    print("phantom_txs_1", phantom_txs_1)
    phantom_hash_1 = phantom_txs_1[0]

    tx_hash2 = cross_space_call.functions.withdrawFromMapped(1).transact({"from": core_accounts[1].address})
    receipt2 = cw3.cfx.wait_for_transaction_receipt(tx_hash2)
    assert receipt2["outcomeStatus"] == 0

    block2 = ew3.eth.get_block(receipt2["blockHash"])
    phantom_txs_2 = block2["transactions"]
    assert len(phantom_txs_2) == 1
    phantom_hash_2 = phantom_txs_2[0]

    assert phantom_hash_1.hex() != phantom_hash_2.hex()


def test_callEVM_phantom_tx_hash_unique(cw3, ew3, core_accounts, evm_accounts, evm_contract, internal_contracts):
    call_hex = evm_contract.encode_abi("emitEVM", [1])
    print("call_hex", call_hex)
    cross_space_call = internal_contracts["CrossSpaceCall"]

    tx_hash1 = cross_space_call.functions.callEVM(evm_contract.address, call_hex).transact({"from": core_accounts[0].address})
    receipt1 = cw3.cfx.wait_for_transaction_receipt(tx_hash1)
    assert receipt1["outcomeStatus"] == 0

    block1 = ew3.eth.get_block(receipt1["blockHash"])
    phantom_txs_1 = block1["transactions"]
    assert len(phantom_txs_1) == 2
    print("phantom_txs_1", phantom_txs_1)
    phantom_hash_1 = phantom_txs_1[1]

    tx_hash2 = cross_space_call.functions.callEVM(evm_contract.address, call_hex).transact({"from": core_accounts[1].address})
    receipt2 = cw3.cfx.wait_for_transaction_receipt(tx_hash2)
    assert receipt2["outcomeStatus"] == 0

    block2 = ew3.eth.get_block(receipt2["blockHash"])
    phantom_txs_2 = block2["transactions"]
    assert len(phantom_txs_2) == 2
    phantom_hash_2 = phantom_txs_2[1]

    assert phantom_hash_1.hex() != phantom_hash_2.hex()
    pass


def transfer_call(internal_contracts, cw3, to):
    cross_space_call = internal_contracts["CrossSpaceCall"]
    tx_hash = cross_space_call.functions.transferEVM(to).transact({"value": 10**18})
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)
    assert receipt["outcomeStatus"] == 0
