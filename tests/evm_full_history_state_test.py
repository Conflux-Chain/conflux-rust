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

    def after_options_parsed(self):
        genesis_account_file = os.path.join(self.options.tmpdir, "genesis_account")
        genesis_account = encode_hex(default_config["GENESIS_PRI_KEY"])
        with open(genesis_account_file, "w") as f:
            # f.write("{},{}".format(genesis_account, default_config["TOTAL_COIN"]))
            f.write("{}".format(genesis_account))
        self.conf_parameters["genesis_secrets"] = f'"{genesis_account_file}"'

    def run_test(self):
        client = RpcClient(self.nodes[0])
        client.generate_empty_blocks(500)
        # This should not raise error if the state is available.
        assert_raises_rpc_error(None, None, client.call, "0x0000000000000000000000000000000000000000", "0x00", None, "0x33")
        self.nodes[0].eth_call({"to": "0x0000000000000000000000000000000000000000", "data": "0x00"}, "0x33")
        assert_raises_rpc_error(None, None, self.nodes[0].eth_call, {"to": "0x0000000000000000000000000000000000000000", "data": "0x00"}, "0x31")

        evm_genesis_account = Web3().eth.account.privateKeyToAccount(default_config["GENESIS_PRI_KEY"]).address
        # value = default_config["TOTAL_COIN"]
        value = 10 ** 18
        self.cross_space_transfer(evm_genesis_account, value)
        client.generate_empty_blocks(500)
        assert_equal(int(self.nodes[0].eth_getBalance(evm_genesis_account, int_to_hex(505)), 0), value)
        assert_raises_rpc_error(None, None, client.get_balance, evm_genesis_account, int_to_hex(505))

    def cross_space_transfer(self, to, value):
        if to.startswith("0x"):
            to = to[2:]
        to = to.lower()
        client = RpcClient(self.nodes[0])
        cross_space = "0x0888000000000000000000000000000000000006"

        data = decode_hex(f"0xda8d5daf{to}000000000000000000000000")
        tx = client.new_tx(value=value, receiver=cross_space, data=data,
                           gas=1000000)
        client.send_tx(tx, True)


if __name__ == "__main__":
    EvmFullHistoryStateTest().main()
