from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.util import assert_raises_rpc_error, assert_equal


# If this errors is changed, please let me know https://github.com/Conflux-Chain/rpc-errors/issues/new


def test_get_tx_by_hash_errors(client: RpcClient):

    assert_raises_rpc_error(
        -32602,
        "Invalid params: invalid length 63, expected a (both 0x-prefixed or not) hex string with length of 64.",
        client.node.cfx_getTransactionByHash,
        "0x88df016429689c079f3b2f6ad39fa052532c56795b733da78a91ebe6a713944",
    )

    assert_raises_rpc_error(
        -32602,
        "Invalid params: invalid type: integer `11`, expected a (both 0x-prefixed or not) hex string with length of 64.",
        client.node.cfx_getTransactionByHash,
        11,
    )

    assert_raises_rpc_error(
        -32602,
        "Invalid params: invalid length 0, expected a (both 0x-prefixed or not) hex string with length of 64.",
        client.node.cfx_getTransactionByHash,
        "0x",
    )
