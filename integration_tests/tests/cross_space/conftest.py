from typing import Type
from conflux_web3 import Web3
import pytest

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.framework_templates import DefaultDevFramework


@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(DefaultDevFramework):
        def set_test_params(self):
            super().set_test_params()
            # self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1
            self.conf_parameters["public_evm_rpc_apis"] = '"all"'  # open all async apis
            self.conf_parameters["executive_trace"] = "true"
        
        def before_test(self):
            super().before_test()

        

    return DefaultFramework

