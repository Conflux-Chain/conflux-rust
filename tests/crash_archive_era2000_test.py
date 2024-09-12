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
class CrashArchiveNodeTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "10"
        self.conf_parameters["era_epoch_count"] = "2000"
        self.conf_parameters["dev_snapshot_epoch_count"] = "20000"
        self.conf_parameters["anticone_penalty_ratio"] = "8"
        self.conf_parameters["dev_allow_phase_change_without_peer"] = "false"
        self.conf_parameters["heartbeat_period_interval_ms"] = "2000"
        self.rpc_timewait = 120

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        for i in range(self.num_nodes):
            self.start_node(i, phase_to_wait=None)

    def setup_network(self):
        self.setup_nodes()
        # Make all nodes fully connected, so a crashed archive node can be connected to another
        # archive node to catch up
        connect_sample_nodes(self.nodes, self.log, sample=self.num_nodes - 1)
        sync_blocks(self.nodes)
        for node in self.nodes:
            node.wait_for_recovery(["NormalSyncPhase"], 30)

    def run_test(self):
        self.nodes[0].test_generateEmptyBlocks(5000)
        self.stop_node(0)
        self.start_node(0, phase_to_wait=None)
        self.stop_node(0)
        self.start_node(0, wait_time=60)
        self.log.info("Pass 1")


if __name__ == "__main__":
    CrashArchiveNodeTest().main()
