import time
from integration_tests.test_framework.util import assert_equal, assert_greater_than_or_equal
    
def test_conflux_context_epochHash(network):
    genesis_hash = network.client.block_by_epoch(0)["hash"]
    for _ in range(5):
        network.client.generate_block_with_parent(genesis_hash)

    wait_for_block(network, 1000)

    test_contract = network.deploy_contract("BlockHash")
    context_contract = network.internal_contract("ConfluxContext")
    for i in range(100, 1001, 100):
        assert_equal(test_contract.functions.getBlockHash(i).call().hex(), network.client.block_by_block_number(i)["hash"][2:])
        assert_equal(context_contract.functions.epochHash(i).call().hex(), network.client.block_by_epoch(i)["hash"][2:])

    network.log.info("Generate 65536+ blocks")
    for i in range(5000, 66000, 5000):
        wait_for_block(network, i)
    wait_for_block(network, 66000)

    assert_equal(test_contract.functions.getBlockHash(100).call().hex(), "0" * 64)
    assert_equal(context_contract.functions.epochHash(100).call().hex(), "0" * 64)
    

def wait_for_block(network, block_number, have_not_reach=False):
    if have_not_reach:
        assert_greater_than_or_equal(
            block_number,  network.client.epoch_number())
    while network.client.epoch_number() < block_number:
        network.client.generate_blocks(
            block_number - network.client.epoch_number())
        time.sleep(0.1)
        network.log.info(f"block_number: {network.client.epoch_number()}")

