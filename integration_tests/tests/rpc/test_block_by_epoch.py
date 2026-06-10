from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.util import assert_raises_rpc_error, assert_equal
from integration_tests.test_framework.util.epoch import (
    epoch_invalid_epoch_type_error,
    epoch_epoch_number_too_large_error,
    epoch_empty_epoch_string_error,
    epoch_invalid_digit_epoch_error,
    epoch_missing_hex_prefix_error,
)


def test_last_mined(client):
    block_hash = client.generate_block()
    block = client.block_by_epoch(client.EPOCH_LATEST_MINED)
    assert_equal(block["hash"], block_hash)


# If this errors is changed, please let me know https://github.com/Conflux-Chain/rpc-errors/issues/new
def test_get_epoch_number_errors(client: RpcClient):
    assert_raises_rpc_error(
        epoch_epoch_number_too_large_error.error_code,
        epoch_epoch_number_too_large_error.error_msg,
        client.block_by_epoch,
        epoch_epoch_number_too_large_error.epoch,
    )
    assert_raises_rpc_error(
        epoch_empty_epoch_string_error.error_code,
        epoch_empty_epoch_string_error.error_msg,
        client.block_by_epoch,
        epoch_empty_epoch_string_error.epoch,
    )
    assert_raises_rpc_error(
        epoch_invalid_digit_epoch_error.error_code,
        epoch_invalid_digit_epoch_error.error_msg,
        client.block_by_epoch,
        epoch_invalid_digit_epoch_error.epoch,
    )

    assert_raises_rpc_error(
        epoch_missing_hex_prefix_error.error_code,
        epoch_missing_hex_prefix_error.error_msg,
        client.block_by_epoch,
        epoch_missing_hex_prefix_error.epoch,
    )


def test_genesis_block_gas_used_is_not_null(client):
    block = client.block_by_epoch(0, True)
    # 0x9402a0 is the sum of all genesis tx's gas limit
    # 300000 + 2800000 + 5000000 + 4*400000 = 9700000
    assert_equal(block["gasUsed"], "0x9402a0")
    assert_equal(len(block["transactions"]), 8)
    tx1 = block["transactions"][1]
    
    assert tx1["blockHash"] is not None
    assert tx1["contractCreated"] is not None
    assert_equal(tx1["transactionIndex"], "0x1")
    assert_equal(tx1["status"], "0x0")


def test_genesis_first_tx_receipt_is_not_null(client):
    block = client.block_by_epoch(0, True)
    first_tx_hash = block["transactions"][0]["hash"]
    receipt = client.get_transaction_receipt(first_tx_hash)
    assert receipt is not None
    
def test_genesis_tx_has_status(client):
    block = client.block_by_epoch(0, True)
    first_tx_hash = block["transactions"][1]["hash"]
    tx = client.get_tx(first_tx_hash)
    assert tx["status"] is not None
    assert tx["contractCreated"] is not None

