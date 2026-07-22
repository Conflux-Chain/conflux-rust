#!/usr/bin/env python3
import datetime

from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt
from web3 import Web3

from conflux import utils
from conflux.address import encode_b32_address
from conflux.utils import encode_hex, bytes_to_int, priv_to_addr, parse_as_int
from conflux.rpc import RpcClient
from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *


# This test is the same as `crash_test.py` except that nodes are launched as archive nodes instead of full nodes
class EvmFullHistoryStateTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "10"
        self.conf_parameters["era_epoch_count"] = "50"
        self.conf_parameters["dev_snapshot_epoch_count"] = "25"
        self.conf_parameters["enable_single_mpt_storage"] = "true"
        self.conf_parameters["single_mpt_space"] = "\"evm\""
        self.conf_parameters["node_type"] = "\"archive\""
        self.conf_parameters["hydra_transition_height"] = 50
        self.conf_parameters["hydra_transition_number"] = 50
        self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(
            int_to_hex(int(2**256 - 1))
        )
        self.rpc_timewait = 120

    def after_options_parsed(self):
        genesis_account_file = os.path.join(self.options.tmpdir, "genesis_account")
        genesis_account = encode_hex(default_config["GENESIS_PRI_KEY"])
        with open(genesis_account_file, "w") as f:
            # f.write("{},{}".format(genesis_account, default_config["TOTAL_COIN"]))
            f.write("{}".format(genesis_account))
        self.conf_parameters["genesis_secrets"] = f'"{genesis_account_file}"'

    def run_test(self):
        client = RpcClient(self.nodes[0])
        client.generate_empty_blocks(100)

        zero_address = "0x0000000000000000000000000000000000000000"
        evm_random_account = Web3().eth.account.create().address
        # value = default_config["TOTAL_COIN"]
        value = 10 ** 18
        tx_hash = self.cross_space_transfer(evm_random_account, value)
        transfer_epoch = client.get_transaction_receipt(tx_hash)["epochNumber"]

        assert_equal(
            int(
                self.nodes[0].eth_getBalance(
                    evm_random_account, transfer_epoch
                ),
                0,
            ),
            value,
        )
        client.get_balance(evm_random_account, transfer_epoch)

        self._advance_until_core_state_pruned(
            client, evm_random_account, transfer_epoch
        )

        assert_raises_rpc_error(
            -32016,
            "out-of-bound",
            client.get_balance,
            evm_random_account,
            transfer_epoch,
        )
        assert_equal(
            int(
                self.nodes[0].eth_getBalance(
                    evm_random_account, transfer_epoch
                ),
                0,
            ),
            value,
        )
        assert_raises_rpc_error(
            -32016,
            "state is not ready",
            client.call,
            zero_address,
            "0x00",
            None,
            int_to_hex(51),
        )
        self.nodes[0].eth_call(
            {"to": zero_address, "data": "0x00"}, int_to_hex(51)
        )
        assert_raises_rpc_error(
            -32016,
            "state is not ready",
            self.nodes[0].eth_call,
            {"to": zero_address, "data": "0x00"},
            int_to_hex(49),
        )

    def _advance_until_core_state_pruned(self, client, account, epoch):
        batch_size = 5
        max_generated_blocks = 1000
        generated_blocks = 0
        rpc_check_failed = False

        def core_state_is_pruned():
            nonlocal generated_blocks, rpc_check_failed
            try:
                if try_rpc(
                    -32016,
                    "out-of-bound",
                    client.get_balance,
                    None,
                    account,
                    epoch,
                ):
                    return True
            except AssertionError:
                rpc_check_failed = True
                raise

            if generated_blocks >= max_generated_blocks:
                return False

            client.generate_empty_blocks(batch_size)
            generated_blocks += batch_size
            return False

        try:
            wait_until(core_state_is_pruned, attempts=201, timeout=120)
        except AssertionError as error:
            if rpc_check_failed:
                raise
            raise AssertionError(
                "Core state was not pruned after generating "
                f"{generated_blocks} blocks: epoch={epoch}, "
                f"latest_state={client.epoch_number('latest_state')}, "
                "latest_checkpoint="
                f"{client.epoch_number('latest_checkpoint')}, "
                f"pos_status={client.pos_status()}"
            ) from error

    def cross_space_transfer(self, to, value):
        if to.startswith("0x"):
            to = to[2:]
        to = to.lower()
        client = RpcClient(self.nodes[0])
        cross_space = "0x0888000000000000000000000000000000000006"

        data = decode_hex(f"0xda8d5daf{to}000000000000000000000000")
        tx = client.new_tx(value=value, receiver=cross_space, data=data,
                           gas=1000000)
        return client.send_tx(tx, True)


if __name__ == "__main__":
    EvmFullHistoryStateTest().main()
