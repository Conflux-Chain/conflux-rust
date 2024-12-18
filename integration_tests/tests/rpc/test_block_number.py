from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.util import assert_equal, assert_raises_rpc_error
import sys


def test_block_number_in_get_block_queries(client: RpcClient):

    #                      ---        ---        ---
    #                  .- | A | <--- | C | <--- | D | <--- ...
    #           ---    |   ---        ---        ---
    # ... <--- | 0 | <-*                          .
    #           ---    |   ---                    .
    #                  .- | B | <..................
    #                      ---

    #               0 --- A --- C --- B --- D ---
    # block number: x  | x+1 | x+2 | x+3 | x+4 |
    # epoch number: y  | y+1 | y+2 |   y + 3   |

    block_0 = client.block_by_epoch("latest_mined")["hash"]
    block_a = client.generate_custom_block(parent_hash=block_0, referee=[], txs=[])
    block_b = client.generate_custom_block(parent_hash=block_0, referee=[], txs=[])
    block_c = client.generate_custom_block(parent_hash=block_a, referee=[], txs=[])
    block_d = client.generate_custom_block(
        parent_hash=block_c, referee=[block_b], txs=[]
    )

    epoch_0 = int(client.block_by_hash(block_0)["height"], 16)
    block_number_0 = int(client.block_by_hash(block_0)["blockNumber"], 16)

    # check block number in `cfx_getBlockByHash`
    assert_equal(
        int(client.block_by_hash(block_a)["blockNumber"], 16), block_number_0 + 1
    )
    assert_equal(
        int(client.block_by_hash(block_c)["blockNumber"], 16), block_number_0 + 2
    )
    assert_equal(
        int(client.block_by_hash(block_b)["blockNumber"], 16), block_number_0 + 3
    )
    assert_equal(
        int(client.block_by_hash(block_d)["blockNumber"], 16), block_number_0 + 4
    )

    # check block number in `cfx_getBlockByEpochNumber`
    epoch_a = hex(epoch_0 + 1)
    assert_equal(
        int(client.block_by_epoch(epoch_a)["blockNumber"], 16), block_number_0 + 1
    )

    epoch_c = hex(epoch_0 + 2)
    assert_equal(
        int(client.block_by_epoch(epoch_c)["blockNumber"], 16), block_number_0 + 2
    )

    # note that this epoch will reference the pivot block (D)
    epoch_d = hex(epoch_0 + 3)
    assert_equal(
        int(client.block_by_epoch(epoch_d)["blockNumber"], 16), block_number_0 + 4
    )


def test_get_block_by_block_number(client: RpcClient):

    #                      ---        ---        ---
    #                  .- | A | <--- | C | <--- | D | <--- ...
    #           ---    |   ---        ---        ---
    # ... <--- | 0 | <-*                          .
    #           ---    |   ---                    .
    #                  .- | B | <..................
    #                      ---

    #               0 --- A --- C --- B --- D ---
    # block number: x  | x+1 | x+2 | x+3 | x+4 |
    # epoch number: y  | y+1 | y+2 |   y + 3   |

    block_0 = client.block_by_epoch("latest_mined")["hash"]
    block_a = client.generate_custom_block(parent_hash=block_0, referee=[], txs=[])
    block_b = client.generate_custom_block(parent_hash=block_0, referee=[], txs=[])
    block_c = client.generate_custom_block(parent_hash=block_a, referee=[], txs=[])
    block_d = client.generate_custom_block(
        parent_hash=block_c, referee=[block_b], txs=[]
    )

    epoch_0 = int(client.block_by_hash(block_0)["height"], 16)
    block_number_0 = int(client.block_by_hash(block_0)["blockNumber"], 16)

    # make sure transactions have been executed
    parent_hash = block_d

    for _ in range(5):
        block = client.generate_custom_block(
            parent_hash=parent_hash, referee=[], txs=[]
        )
        parent_hash = block

    # check blocks by block number
    assert_equal(
        client.block_by_block_number(hex(block_number_0)), client.block_by_hash(block_0)
    )

    assert_equal(
        client.block_by_block_number(hex(block_number_0 + 1)),
        client.block_by_hash(block_a),
    )

    assert_equal(
        client.block_by_block_number(hex(block_number_0 + 2)),
        client.block_by_hash(block_c),
    )

    assert_equal(
        client.block_by_block_number(hex(block_number_0 + 3)),
        client.block_by_hash(block_b),
    )

    assert_equal(
        client.block_by_block_number(hex(block_number_0 + 4)),
        client.block_by_hash(block_d),
    )


# If this errors is changed, please let me know https://github.com/Conflux-Chain/rpc-errors/issues/new
def test_get_block_by_epoch_number_errors(client: RpcClient):

    try:
        client.block_by_epoch(sys.maxsize)
    except Exception as e:
        assert_equal(
            e.response.message,
            "Invalid params: expected a numbers with less than largest epoch number.",
        )
        assert_equal(e.response.code, -32602)

    try:
        client.block_by_epoch("0x")
    except Exception as e:
        assert_equal(
            e.response.message,
            "Invalid params: Invalid epoch number: cannot parse integer from empty string.",
        )
        assert_equal(e.response.code, -32602)

    try:
        client.block_by_epoch("0xZZZ")
    except Exception as e:
        assert_equal(
            e.response.message,
            "Invalid params: Invalid epoch number: invalid digit found in string.",
        )
        assert_equal(e.response.code, -32602)

    try:
        client.block_by_epoch(-1)
    except Exception as e:
        assert_equal(
            e.response.message,
            "Invalid params: Invalid epoch number: missing 0x prefix.",
        )
        assert_equal(e.response.code, -32602)

    assert_raises_rpc_error(
        -32602,
        "Invalid params: invalid type: sequence, expected a (both 0x-prefixed or not) hex string with length between (0; 16].",
        client.block_by_block_number,
        [],
    )
