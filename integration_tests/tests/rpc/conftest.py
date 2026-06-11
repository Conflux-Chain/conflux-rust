import pytest
from typing import Type
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient

@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class RpcTestFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["base_fee_burn_transition_height"] = 1
            self.conf_parameters["base_fee_burn_transition_number"] = 1
            self.conf_parameters["execute_genesis"] = "true"

        def setup_network(self):
            self.setup_nodes()
            self.rpc = RpcClient(self.nodes[0])

    return RpcTestFramework

@pytest.fixture(scope="module")
def client(network: ConfluxTestFramework) -> RpcClient:
    return network.client
