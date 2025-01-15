import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util import *
from eth_utils import decode_hex
from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.blocktools import encode_hex_0x

@pytest.fixture(scope="module")
def framework_class():
    class Framework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 2
            self.conf_parameters["evm_chain_id"] = str(10)
            self.conf_parameters["evm_transaction_block_ratio"] = str(1)
            self.conf_parameters["executive_trace"] = "true"
            self.conf_parameters["cip1559_transition_height"] = str(1)
            # self.conf_parameters["min_eth_base_price"] = 20 * (10**9)
            self.conf_parameters["tx_pool_allow_gas_over_half_block"] = "true"

        def setup_network(self):
            self.setup_nodes()
            self.rpc = RpcClient(self.nodes[0])
    return Framework

def test_cross_space_transfer(cw3, ew3, erc20_contract, evm_accounts, network):
    csc_contract = cw3.cfx.contract(name="CrossSpaceCall", with_deployment_info=True)
    new_account = ew3.eth.account.create()
    receipt = csc_contract.functions.transferEVM(new_account.address).transact({
        "value": cw3.to_wei(1, "ether")
    }).executed()
    epoch = receipt["epochNumber"]
    ret = network.nodes[0].debug_getTransactionsByEpoch(hex(epoch))
    assert_equal(len(ret), 1)

def test_tx_and_receipt(ew3, evm_accounts, receiver_account, network):
    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)
    tx_hash = ew3.eth.send_transaction({
        "from": account.address,
        "to": receiver_account.address,
        "value": ew3.to_wei(1, "ether"),
        "gasPrice": 1,
        "gas": 21000,
        "nonce": nonce,
    })
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1
    assert receipt["gasUsed"] == 21000
    assert receipt["gasFee"] == "0x5208"
    assert receipt["txExecErrorMsg"] == None

    tx = ew3.eth.get_transaction(tx_hash)
    ret1 = network.nodes[0].debug_getTransactionsByEpoch(hex(receipt["blockNumber"]))
    ret2 = network.nodes[0].debug_getTransactionsByBlock(encode_hex_0x(tx["blockHash"]))
    assert len(ret1) == 1
    assert len(ret2) == 1
    assert ret1[0] == ret2[0]