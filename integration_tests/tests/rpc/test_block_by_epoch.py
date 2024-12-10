from integration_tests.test_framework.util import assert_equal

def test_last_mined(client):
    block_hash = client.generate_block()
    block = client.block_by_epoch(client.EPOCH_LATEST_MINED)
    assert_equal(block["hash"], block_hash)
