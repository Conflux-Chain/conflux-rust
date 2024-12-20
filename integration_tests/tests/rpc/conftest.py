import pytest
from dataclasses import dataclass
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient
from typing import Any, Callable, List
from sys import maxsize
from integration_tests.test_framework.util import assert_raises_rpc_error


@pytest.fixture(scope="module")
def client(network: ConfluxTestFramework) -> RpcClient:
    return network.rpc


@dataclass
class InvalidCase:
    param: Any
    error_msg: str


@pytest.fixture
def invalid_params_epoch():
    class Helper:
        common_invalid_case = {
            "Invalid_parameter_type": InvalidCase(
                1,
                "Invalid params: invalid type: integer `1`, expected an epoch number or 'latest_mined', 'latest_state', 'latest_checkpoint', 'latest_finalized', 'latest_confirmed' or 'earliest'.",
            ),
            "epoch_number_too_large": InvalidCase(
                hex(maxsize),
                "Invalid params: expected a numbers with less than largest epoch number.",
            ),
            "empty_value": InvalidCase(
                "0x",
                "Invalid params: Invalid epoch number: cannot parse integer from empty string.",
            ),
            "invalid_hex_format": InvalidCase(
                "0xZZZ",
                "Invalid params: Invalid epoch number: invalid digit found in string.",
            ),
            "missing_hex_type": InvalidCase(
                hex(-1), "Invalid params: Invalid epoch number: missing 0x prefix."
            ),
        }

        def check_invalid_epoch_param(self, client_method: Callable, case: InvalidCase):
            assert_raises_rpc_error(-32602, case.error_msg, client_method, case.param)

        def check_cases(self, rpc_method: Callable, cases: List[InvalidCase]):
            for case in cases:
                self.check_invalid_epoch_param(rpc_method, case)

    return Helper()
