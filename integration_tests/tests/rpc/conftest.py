import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.framework_templates import DefaultDevFramework
from typing import Type

@pytest.fixture(scope="module")
def client(network: ConfluxTestFramework) -> RpcClient:
    return network.client

@pytest.fixture(scope="module")
def framework_class():
    class InternalContractTestEnv(DefaultDevFramework):
        def set_test_params(self):
            super().set_test_params()
            self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["base_fee_burn_transition_height"] = 1
            self.conf_parameters["base_fee_burn_transition_number"] = 1

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])
    return InternalContractTestEnv
