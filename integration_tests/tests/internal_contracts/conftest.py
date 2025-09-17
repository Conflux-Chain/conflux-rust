import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.framework_templates import DefaultDevFramework

@pytest.fixture(scope="module")
def client(network: ConfluxTestFramework) -> RpcClient:
    return network.client

@pytest.fixture(scope="module")
def framework_class():
    return DefaultDevFramework
