from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.util import assert_equal, assert_raises_rpc_error
import sys


# If this errors is changed, please let me know https://github.com/Conflux-Chain/rpc-errors/issues/new
def test_get_block_by_epoch_number_errors(client: RpcClient):
    assert_raises_rpc_error(
        -32602,
        "Invalid params: invalid type: integer `1`, expected an epoch number or 'latest_mined', 'latest_state', 'latest_checkpoint', 'latest_finalized', 'latest_confirmed' or 'earliest'.",
        client.epoch_number,
        1,
    )
    assert_raises_rpc_error(
        -32602,
        "Invalid params: expected a numbers with less than largest epoch number.",
        client.epoch_number,
        hex(sys.maxsize),
    )
    assert_raises_rpc_error(
        -32602,
        "Invalid params: Invalid epoch number: cannot parse integer from empty string.",
        client.epoch_number,
        "0x",
    )
    assert_raises_rpc_error(
        -32602,
        "Invalid params: Invalid epoch number: invalid digit found in string.",
        client.epoch_number,
        "0xZZZ",
    )

    assert_raises_rpc_error(
        -32602,
        "Invalid params: Invalid epoch number: missing 0x prefix.",
        client.epoch_number,
        hex(-1),
    )
