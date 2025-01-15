from integration_tests.test_framework.util import assert_greater_than

def test_block_tag(network, ew3):
    network.nodes[0].test_generateEmptyBlocks(2000)
    blocks = [
        ew3.eth.get_block("finalized"),
        ew3.eth.get_block("safe"),
        ew3.eth.get_block("latest"),
    ]
    assert_greater_than(blocks[1]["number"], blocks[0]["number"]) # type: ignore
    assert_greater_than(blocks[2]["number"], blocks[1]["number"]) # type: ignore