import pytest
from typing import Tuple
from integration_tests.conflux.rpc import RpcClient, default_config
from integration_tests.test_framework.util import (
    assert_equal,
)

from cfx_account import Account as CfxAccount
from cfx_account.signers.local import LocalAccount as CfxLocalAccount

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util import (
    generate_blocks_for_base_fee_manipulation,
    generate_single_block_for_base_fee_manipulation,
    assert_correct_fee_computation_for_core_tx,
)

MIN_NATIVE_BASE_PRICE = 10000
BURNT_RATIO = 0.5


@pytest.fixture(scope="module")
def framework_class():
    class CIP137TestEnv(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["min_native_base_price"] = MIN_NATIVE_BASE_PRICE
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])
            self.rpc = RpcClient(self.nodes[0])

    return CIP137TestEnv


# We need to ensure that the tx in B block
# B and ending block will be in the same epoch
#                      ---        ---        ---        ---        ---        ---
#                  .- | A | <--- | C | <--- | D | <--- | E | <--- | F | <--- | G | ...
#           ---    |   ---        ---        ---        ---        ---        ---
# ... <--- | P | <-*                                                           .
#           ---    |   ---                                                     .
#                  .- | B | <...................................................
#                      ---
# ensures txs to be included in B block and the ending block (e.g. F) base gas price is greater than the specified target_minimum_base_fee (not guaranteed to be the first block)
# returns the ending block hash
def construct_non_pivot_block(
    network: ConfluxTestFramework,
    acct: CfxLocalAccount,
    txs: list,
    starting_block_hash: str = None,
    epoch_delta: int = 6,  # 1.125^6 -> 2.027 which would make the initial tx invalid
) -> Tuple[str, str]:

    if epoch_delta <= 0:
        raise ValueError("epoch_delta must be positive")

    if starting_block_hash is None:
        starting_block_hash = network.rpc.block_by_epoch("latest_mined")["hash"]

    # create the non-pivot block
    non_pivot_block = network.rpc.generate_custom_block(
        parent_hash=starting_block_hash, txs=txs, referee=[]
    )
    ending_but_two_block, account_next_nonce = (
        generate_blocks_for_base_fee_manipulation(
            network.rpc, acct, epoch_delta - 1, initial_parent_hash=starting_block_hash
        )
    )
    ending_block, _ = generate_single_block_for_base_fee_manipulation(
        network.rpc,
        acct,
        [non_pivot_block],
        parent_hash=ending_but_two_block,
        starting_nonce=account_next_nonce,
    )
    return non_pivot_block, ending_block


def init_acct_with_cfx(
    network: ConfluxTestFramework, drip: int = 10**21
) -> CfxLocalAccount:
    network.rpc.send_tx(
        network.rpc.new_tx(
            receiver=(acct := CfxAccount.create()).address,
            value=drip,
            gas_price=max(
                network.rpc.base_fee_per_gas() * 2, MIN_NATIVE_BASE_PRICE
            ),  # avoid genisis zero gas price
        ),
        True,
    )
    return acct


def get_gas_charged(network: ConfluxTestFramework, tx_hash: str) -> int:
    gas_limit = int(network.rpc.get_tx(tx_hash)["gas"], 16)
    gas_used = int(network.rpc.get_transaction_receipt(tx_hash)["gasUsed"], 16)
    return max(int(3 / 4 * gas_limit), gas_used)


def test_cip137(network: ConfluxTestFramework):
    acct1 = init_acct_with_cfx(network)
    acct2 = init_acct_with_cfx(network)

    block_p = network.rpc.block_by_epoch("latest_mined")["hash"]

    gas_price_level_1 = MIN_NATIVE_BASE_PRICE
    gas_price_level_1_5 = int(MIN_NATIVE_BASE_PRICE * 1.5)
    gas_price_level_2 = network.rpc.base_fee_per_gas() * 10

    acct1_txs = [
        network.rpc.new_typed_tx(
            receiver=network.rpc.rand_addr(),
            priv_key=acct1.key,
            nonce=0,
            max_fee_per_gas=gas_price_level_2,
        ),  # expected to succeed
        network.rpc.new_typed_tx(
            receiver=network.rpc.rand_addr(),
            priv_key=acct1.key,
            nonce=1,
            max_fee_per_gas=gas_price_level_1_5,
        ),  # expected to succeed with max fee less than epoch base gas fee
        network.rpc.new_tx(
            receiver=network.rpc.rand_addr(),
            priv_key=acct1.key,
            nonce=2,
            gas_price=gas_price_level_1,
        ),  # expected to be ignored and can be resend later
        network.rpc.new_tx(
            receiver=network.rpc.rand_addr(),
            priv_key=acct1.key,
            nonce=3,
            gas_price=gas_price_level_2,
        ),  # expected to be ignored
    ]

    acct2_txs = [
        network.rpc.new_tx(
            receiver=network.rpc.rand_addr(),
            priv_key=acct2.key,
            nonce=0,
            gas_price=gas_price_level_2,
        ),  # expected to succeed
        network.rpc.new_tx(
            receiver=network.rpc.rand_addr(),
            priv_key=acct2.key,
            nonce=1,
            gas_price=gas_price_level_2,
        ),  # expected to succeed
        network.rpc.new_tx(
            receiver=network.rpc.rand_addr(),
            priv_key=acct2.key,
            nonce=2,
            gas_price=gas_price_level_2,
        ),  # expected to succeed
    ]

    block_b, block_f = construct_non_pivot_block(
        network,
        CfxAccount.from_key(default_config["GENESIS_PRI_KEY"]),
        [*acct1_txs, *acct2_txs],
        starting_block_hash=block_p,
        epoch_delta=6,  # 1.125^6 -> 2.03
    )

    network.log.info(f"current base fee per gas: {network.rpc.base_fee_per_gas()}")

    # we are ensuring the gas price order:
    # gas_price_level_1 < current_base_fee * burnt_ratio < gas_price_level_1_5  < current_base_fee < gas_price_level_2
    assert gas_price_level_2 > network.rpc.base_fee_per_gas() * BURNT_RATIO
    assert (
        gas_price_level_1 < network.rpc.base_fee_per_gas() * BURNT_RATIO
    ), f"gas_price_level_1 {gas_price_level_1} should be less than {network.rpc.base_fee_per_gas() * BURNT_RATIO}"

    # wait for epoch of block f executed
    parent_block = block_f
    for _ in range(30):
        block = network.rpc.generate_custom_block(
            parent_hash=parent_block, referee=[], txs=[]
        )
        parent_block = block

    assert_equal(network.rpc.get_nonce(acct1.address), 2)
    assert_equal(network.rpc.get_nonce(acct2.address), 3)
    focusing_block = network.rpc.block_by_hash(block_b, True)
    epoch = int(focusing_block["epochNumber"], 16)

    network.log.info(f"epoch of block b: {epoch}")
    network.log.info(f"heigth of block b: {int(focusing_block['height'], 16)}")
    network.log.info(
        f"base_fee_per_gas for epoch {epoch}: {network.rpc.base_fee_per_gas(epoch)}"
    )
    network.log.info(
        f"burnt_fee_per_gas for epoch {epoch}: {network.rpc.base_fee_per_gas(epoch) * 0.5}"
    )
    network.log.info(
        f"least base fee for epoch {epoch}: {network.rpc.base_fee_per_gas(epoch) * BURNT_RATIO}"
    )
    network.log.info(
        f"transactions in block b: {network.rpc.block_by_hash(block_b)['transactions']}"
    )

    assert_equal(focusing_block["transactions"][0]["status"], "0x0")
    assert_equal(focusing_block["transactions"][1]["status"], "0x0")
    assert_equal(focusing_block["transactions"][2]["status"], None)
    assert_equal(focusing_block["transactions"][2]["blockHash"], None)
    assert_equal(focusing_block["transactions"][3]["status"], None)
    assert_equal(focusing_block["transactions"][3]["blockHash"], None)

    # as comparison
    assert_equal(focusing_block["transactions"][4]["status"], "0x0")
    assert_equal(focusing_block["transactions"][5]["status"], "0x0")
    assert_equal(focusing_block["transactions"][6]["status"], "0x0")

    for tx_hash in network.rpc.block_by_hash(block_b)["transactions"]:
        assert_correct_fee_computation_for_core_tx(network.rpc, tx_hash, BURNT_RATIO)

    network.rpc.generate_blocks(20, 5)

    # transactions shall be sent back to txpool and then get packed
    assert_equal(network.rpc.get_nonce(acct1.address), 4)
