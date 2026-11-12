from typing import Type

import pytest
from web3 import Web3

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util import assert_raises_web3_rpc_error


U256_MAX = (1 << 256) - 1
RECIPIENT = "0x1000000000000000000000000000000000000001"
SENDER = "0x1000000000000000000000000000000000000002"


@pytest.fixture(scope="module")
def framework_class(
    framework_class: Type[ConfluxTestFramework],
) -> Type[ConfluxTestFramework]:
    class OverflowFramework(framework_class):
        def set_test_params(self):
            super().set_test_params()
            # The genesis tool generates proofs using the fixed Sigma protocol.
            self.conf_parameters["sigma_fix_transition_number"] = 0
            self.conf_parameters["base_fee_burn_transition_height"] = 1
            self.conf_parameters["base_fee_burn_transition_number"] = 1

    return OverflowFramework


@pytest.mark.parametrize("method", ["eth_estimateGas", "eth_call"])
def test_overridden_recipient_balance_saturates(ew3: Web3, method: str) -> None:
    balance_before = ew3.eth.get_balance(RECIPIENT)
    request = {"to": RECIPIENT, "value": "0x1", "gas": "0x186a0"}
    overrides = {
        RECIPIENT: {
            "balance": hex(U256_MAX),
            # Return SELFBALANCE after receiving the value.
            "code": "0x4760005260206000f3",
        }
    }

    result = ew3.manager.request_blocking(
        method, [request, "latest", overrides]
    )
    if method == "eth_call":
        assert result == f"0x{U256_MAX:064x}"
    else:
        assert 21000 < int(result, 16) <= int(request["gas"], 16)

    # Saturation and overrides must remain local to the simulation.
    assert ew3.eth.get_balance(RECIPIENT) == balance_before
    assert ew3.manager.request_blocking("eth_estimateGas", [request]) == "0x5208"


@pytest.mark.parametrize(
    "balance,value,self_transfer",
    [
        (U256_MAX - 1, 1, False),
        (U256_MAX, 0, False),
        (U256_MAX, 1, True),
    ],
)
def test_overridden_balance_boundaries(
    ew3: Web3, balance: int, value: int, self_transfer: bool
) -> None:
    balance_before = ew3.eth.get_balance(RECIPIENT)
    request = {"to": RECIPIENT, "value": hex(value), "gas": "0x5208"}
    if self_transfer:
        request["from"] = RECIPIENT
    overrides = {RECIPIENT: {"balance": hex(balance)}}

    # A self-transfer debits the same account before crediting it.
    assert ew3.manager.request_blocking(
        "eth_estimateGas", [request, "latest", overrides]
    ) == "0x5208"
    assert ew3.eth.get_balance(RECIPIENT) == balance_before


@pytest.mark.parametrize(
    "gas_price", [U256_MAX // 21000, U256_MAX // 21000 + 1, U256_MAX]
)
@pytest.mark.parametrize("has_sender", [False, True])
def test_estimated_fee_overflow(
    ew3: Web3, gas_price: int, has_sender: bool
) -> None:
    # Omit gas to exercise fee calculation after successful virtual execution.
    request = {
        "to": RECIPIENT,
        "value": "0x0",
        "gasPrice": hex(gas_price),
        "type": "0x0",
    }
    if has_sender:
        request["from"] = SENDER
        assert assert_raises_web3_rpc_error(
            -32003,
            "insufficient funds",
            ew3.manager.request_blocking,
            "eth_estimateGas",
            [request],
        )
    else:
        assert ew3.manager.request_blocking("eth_estimateGas", [request]) == "0x5208"

    assert ew3.eth.get_balance(SENDER) == 0
