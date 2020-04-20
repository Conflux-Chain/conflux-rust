#!/usr/bin/env python3
import os
import sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from test_framework.block_gen_thread import BlockGenThread
from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt
from conflux import utils
from conflux.rpc import RpcClient
from conflux.utils import encode_hex, bytes_to_int, priv_to_addr, parse_as_int
from test_framework.blocktools import create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 8
        self.conf_parameters["generate_tx"] = "true"
        # Every node generates 1 tx every second
        self.conf_parameters["generate_tx_period_us"] = "50000"
        self.conf_parameters["throttling_conf"] = '"throttling.conf"'
        throttling_setting = "20,10,10,1,10"
        self.extra_conf_files = {
            "throttling.conf":
                f"""\
                [rpc]
                [rpc_local]
                [sync_protocol]
                NewBlockHashes="{throttling_setting}"
                Transactions="{throttling_setting}"
                GetBlockHeaders="{throttling_setting}"
                NewBlock="{throttling_setting}"
                GetBlocks="{throttling_setting}"
                GetCompactBlocks="{throttling_setting}"
                GetBlockTxn="{throttling_setting}"
                DynamicCapabilityChange="{throttling_setting}"
                TransactionDigests="{throttling_setting}"
                GetTransactions="{throttling_setting}"
                GetTransactionsFromTxHashes="{throttling_setting}"
                GetBlockHashesByEpoch="{throttling_setting}"
                SnapshotManifestRequest="{throttling_setting}"
                SnapshotChunkRequest="{throttling_setting}"
                Throttled="{throttling_setting}"
                [light_protocol]\
                """
        }
    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        block_gen_thread = BlockGenThread(self.nodes, self.log, interval_base=0.01)
        block_gen_thread.start()
        time.sleep(10)
        block_gen_thread.stop()
        self.log.info("Wait for blocks to be synced")
        sync_blocks(self.nodes, timeout=120)
        self.log.info("Pass")


if __name__ == "__main__":
    P2PTest().main()
