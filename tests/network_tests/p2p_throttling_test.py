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


class P2PThrottlingTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["generate_tx"] = "true"
        self.conf_parameters["generate_tx_period_us"] = "50000"

        # Token bucket: <max_tokens>,<init_tokens>,<recharge_rate>,<default_cost>,<max_throttled_tolerates>
        # These parameters are set to ensure that throttling will be triggered,
        # and will not exceed max_throttled_tolerates.
        self.throttling_array = [20, 10, 10, 1, 50]
        throttling_setting = ",".join([str(i) for i in self.throttling_array])
        throttling_file = "throttling.toml"
        self.conf_parameters["throttling_conf"] = f"\"{throttling_file}\""
        # Use heartbeat to trigger block sync from terminals.
        self.conf_parameters["heartbeat_period_interval_ms"] = "1000"
        self.extra_conf_files = {
            f"{throttling_file}":
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
        n_blocks = 200
        rate = self.throttling_array[2]
        init_token = self.throttling_array[0]
        max_throttled_tolerates = self.throttling_array[4]
        start = time.time()
        # Generate blocks with about twice the throttling rate.
        for _ in range(int(n_blocks/rate)):
            self.nodes[0].generate_empty_blocks(rate)
            time.sleep(0.5)
        self.log.info("Wait for blocks to be synced")
        sync_blocks(self.nodes, timeout=120)
        elapsed = time.time() - start
        assert elapsed > (n_blocks - init_token - max_throttled_tolerates) /rate
        self.log.info(f"Pass with {elapsed} seconds")


if __name__ == "__main__":
    P2PThrottlingTest().main()
