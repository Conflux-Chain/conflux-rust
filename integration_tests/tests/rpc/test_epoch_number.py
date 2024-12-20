from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.util import assert_equal, assert_raises_rpc_error
import sys


# If this errors is changed, please let me know https://github.com/Conflux-Chain/rpc-errors/issues/new
def test_get_epoch_number_errors(client: RpcClient, invalid_params_epoch):

    invalid_params_epoch.check_cases(
        client.epoch_number, list(invalid_params_epoch.common_invalid_case.values())
    )
