from typing import Type
from conflux_web3 import Web3
import pytest

from integration_tests.test_framework.test_framework import ConfluxTestFramework


@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            # self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1
            self.conf_parameters["public_evm_rpc_async_apis"] = '"all"'  # open all async apis
            self.conf_parameters["executive_trace"] = "true"
        
        def before_test(self):
            super().before_test()

        

    return DefaultFramework

