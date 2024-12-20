from integration_tests.test_framework.util import assert_equal

def test_last_mined(client):
    block_hash = client.generate_block()
    block = client.block_by_epoch(client.EPOCH_LATEST_MINED)
    assert_equal(block["hash"], block_hash)


# If this errors is changed, please let me know https://github.com/Conflux-Chain/rpc-errors/issues/new
def test_block_by_epoch_error(client, invalid_params_epoch):
    # this rpc epoch number is required, so it allowing the passing of a numerical value (not a hexadecimal string ?).

    invalid_params_epoch.check_cases(
        client.block_by_epoch,
        [
            invalid_params_epoch.common_invalid_case["epoch_number_too_large"],
            invalid_params_epoch.common_invalid_case["empty_value"],
            invalid_params_epoch.common_invalid_case["invalid_hex_format"],
            invalid_params_epoch.common_invalid_case["missing_hex_type"],
        ],
    )
    # this rpc has below errors, but the parameter is checked before the rpc is called, so the error is not raised.
    # Epoch number larger than the current pivot chain tip
    # get_hash_from_epoch_number: Epoch hash set not in db, epoch_number=
    
