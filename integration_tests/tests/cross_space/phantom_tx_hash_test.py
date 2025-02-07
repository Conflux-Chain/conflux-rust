import pytest

from integration_tests.test_framework.test_framework import ConfluxTestFramework


@pytest.fixture(scope="module")
def evm_contract(network: ConfluxTestFramework):
    return network.deploy_evm_contract("CrossSpaceEventTestEVMSide")


def test_phantom_tx_hash_unique(cw3, ew3, core_accounts, evm_accounts, evm_contract,network):
    
    pass
