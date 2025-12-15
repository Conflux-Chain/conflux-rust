import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient

@pytest.fixture(scope="module")
def framework_class():
    class DefaultFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1
            self.conf_parameters["public_evm_rpc_apis"] = "\"all\"" # open all async apis
            # self.conf_parameters["evm_chain_id"] = str(10)
            # self.conf_parameters["evm_transaction_block_ratio"] = str(1)
            self.conf_parameters["executive_trace"] = "true"

        def setup_network(self):
            self.setup_nodes()
            self.rpc = RpcClient(self.nodes[0])

    return DefaultFramework

def test_espace_block_gas_limit(network, ew3):
    network.nodes[0].test_generateEmptyBlocks(100)
    block_number = ew3.eth.get_block("latest")["number"]
    for i in range(1, block_number):
        block = ew3.eth.get_block(i)
        assert block["gasLimit"] == 30000000
        if i % 5 == 0:
            assert block["espaceGasLimit"] != "0x0"
        else:
            assert block["espaceGasLimit"] == "0x0"