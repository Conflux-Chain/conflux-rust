import pytest
from conflux_web3 import Web3
from conflux_web3.contract import ConfluxContract
from integration_tests.test_framework.framework_templates import DefaultPoSFramework
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util import wait_until
from typing import Type

@pytest.fixture(scope="module")
def conflux_context(cw3: Web3):
    return cw3.cfx.contract(name="ConfluxContext", with_deployment_info=True)

@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    return DefaultPoSFramework

# autouse this fixture to wait for the pos epoch to be higher than 1
@pytest.fixture(scope="module", autouse=True)
def high_pos_height(client):
    def wait():
        client.generate_empty_blocks(60)
        return int(client.pos_status()["epoch"], 0) > 1
    wait_until(wait, timeout=120)

def test_conflux_context_epochNumber(cw3: Web3, conflux_context: ConfluxContract):
    assert conflux_context.functions.epochNumber().call() == cw3.cfx.epoch_number_by_tag("latest_state") + 1

def test_conflux_context_posHeight(client, cw3: Web3, conflux_context: ConfluxContract): 
    referred_pos_block_hash = cw3.cfx.get_block("latest_state")["posReference"]
    posBlockHeight = conflux_context.functions.posHeight().call()
    assert client.pos_get_block(posBlockHeight)["hash"] == referred_pos_block_hash.to_0x_hex() # type: ignore

def test_conflux_context_finalizedEpochNumber(cw3: Web3, conflux_context: ConfluxContract):
    assert conflux_context.functions.finalizedEpochNumber().call() == cw3.cfx.epoch_number_by_tag("latest_finalized")