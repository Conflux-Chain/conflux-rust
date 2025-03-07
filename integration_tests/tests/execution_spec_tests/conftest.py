import pytest

from functools import partial
from web3 import Web3

from ethereum_test_tools import (
    Environment,
)

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util.adapter import AllocMock, conflux_state_test

def pytest_configure(config):
    """Register the with_all_call_opcodes marker"""
    config.addinivalue_line(
        "markers", "with_all_call_opcodes: Parameterize tests with all call opcodes"
    )
    config.addinivalue_line(
        "markers", "with_all_create_opcodes: Parameterize tests with all create opcodes"
    )
    config.addinivalue_line(
        "markers", "with_all_precompiles: Parameterize tests with all precompiles"
    )

@pytest.fixture(scope="module")
def state_test(ew3: Web3, network: ConfluxTestFramework):
    # Use functools.partial to curry the function with ew3 and network parameters
    return partial(conflux_state_test, ew3, network)

@pytest.fixture(scope="module")
def blockchain_test(ew3: Web3, network: ConfluxTestFramework):
    return partial(conflux_state_test, ew3, network, env=Environment())

@pytest.fixture(scope="module")
def pre(ew3, evm_accounts):
    return AllocMock(ew3, evm_accounts[-1])
