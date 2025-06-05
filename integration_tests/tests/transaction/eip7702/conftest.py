import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework

MIN_NATIVE_BASE_PRICE = 10000
EVM_CHAIN_ID = 11

@pytest.fixture(scope="module")
def framework_class():
    class EIP7702TestEnv(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["evm_chain_id"] = str(EVM_CHAIN_ID)
            self.conf_parameters["min_native_base_price"] = MIN_NATIVE_BASE_PRICE
            self.conf_parameters["eoa_code_transition_height"] = 1
            self.conf_parameters["align_evm_transition_height"] = 1
            self.conf_parameters["evm_transaction_block_ratio"] = str(1)
            self.conf_parameters["public_evm_rpc_apis"] = '"all"'
            self.conf_parameters["executive_trace"] = "true"

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])

    return EIP7702TestEnv