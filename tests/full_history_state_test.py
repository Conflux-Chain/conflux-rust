#!/usr/bin/env python3
import datetime

from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt

from conflux import utils
from conflux.utils import encode_hex, bytes_to_int, priv_to_addr, parse_as_int
from conflux.rpc import RpcClient
from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *


# This test is the same as `crash_test.py` except that nodes are launched as archive nodes instead of full nodes
class FullHistoryStateTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "10"
        self.conf_parameters["era_epoch_count"] = "50"
        self.conf_parameters["dev_snapshot_epoch_count"] = "25"
        self.conf_parameters["enable_single_mpt_storage"] = "true"
        self.conf_parameters["node_type"] = "\"archive\""
        self.rpc_timewait = 120

    def run_test(self):
        client = RpcClient(self.nodes[0])
        client.generate_empty_blocks(500)
        # This should not raise error if the state is available.
        client.call("0x0000000000000000000000000000000000000000", "0x00", epoch="0x1")
        assert_equal(client.get_balance(eth_utils.encode_hex(priv_to_addr(default_config["GENESIS_PRI_KEY"])), epoch="0x1"), default_config["TOTAL_COIN"])
        # Check the block reward is correct.
        assert_equal(client.get_balance("0x0000000000000000000000000000000000000000", epoch="0x33"), 7000000000118911719 * (51 - 12))


if __name__ == "__main__":
    FullHistoryStateTest().main()
