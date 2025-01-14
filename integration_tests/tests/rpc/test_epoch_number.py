from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.util import assert_raises_rpc_error
from integration_tests.test_framework.util.epoch import (
    epoch_invalid_epoch_type_error,
    epoch_epoch_number_too_large_error,
    epoch_empty_epoch_string_error,
    epoch_invalid_digit_epoch_error,
    epoch_missing_hex_prefix_error,
)


# If this errors is changed, please let me know https://github.com/Conflux-Chain/rpc-errors/issues/new
def test_get_epoch_number_errors(client: RpcClient):
    assert_raises_rpc_error(
        epoch_invalid_epoch_type_error.error_code,
        epoch_invalid_epoch_type_error.error_msg,
        client.epoch_number,
        epoch_invalid_epoch_type_error.epoch,
    )
    assert_raises_rpc_error(
        epoch_epoch_number_too_large_error.error_code,
        epoch_epoch_number_too_large_error.error_msg,
        client.epoch_number,
        epoch_epoch_number_too_large_error.epoch,
    )
    assert_raises_rpc_error(
        epoch_empty_epoch_string_error.error_code,
        epoch_empty_epoch_string_error.error_msg,
        client.epoch_number,
        epoch_empty_epoch_string_error.epoch,
    )
    assert_raises_rpc_error(
        epoch_invalid_digit_epoch_error.error_code,
        epoch_invalid_digit_epoch_error.error_msg,
        client.epoch_number,
        epoch_invalid_digit_epoch_error.epoch,
    )

    assert_raises_rpc_error(
        epoch_missing_hex_prefix_error.error_code,
        epoch_missing_hex_prefix_error.error_msg,
        client.epoch_number,
        epoch_missing_hex_prefix_error.epoch,
    )
