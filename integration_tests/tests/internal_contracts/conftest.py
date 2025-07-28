import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient

@pytest.fixture(scope="module")
def client(network: ConfluxTestFramework) -> RpcClient:
    return network.client
