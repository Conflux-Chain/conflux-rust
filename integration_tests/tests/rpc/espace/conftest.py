import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient
from typing import Type

@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1
            self.conf_parameters["public_evm_rpc_async_apis"] = "\"all\"" # open all async apis

        def setup_network(self):
            self.setup_nodes()
            self.rpc = RpcClient(self.nodes[0])

    return DefaultFramework