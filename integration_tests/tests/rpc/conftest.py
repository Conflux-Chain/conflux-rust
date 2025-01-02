import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient

@pytest.fixture(scope="module")
def client(network: ConfluxTestFramework) -> RpcClient:
    return network.rpc

# espace rpc method caller
@pytest.fixture(scope="module")
def call_rpc(ew3):
    def do_call_rpc(method, params=[]):
        return ew3.manager.request_blocking(method, params)
    return do_call_rpc