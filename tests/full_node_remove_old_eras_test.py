#!/usr/bin/env python3
import os
import eth_utils
import time

from conflux.config import default_config
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "contracts/EventsTestContract_bytecode.dat"
CALLED_TOPIC = encode_hex_0x(keccak(b"Called(address,uint32)"))

ARCHIVE_NODE = 0
FULL_NODE = 1

ERA_EPOCH_COUNT = 100

class FullNodeRemoveOldErasTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

        # set era and snapshot length
        self.conf_parameters["era_epoch_count"] = str(ERA_EPOCH_COUNT)
        self.conf_parameters["dev_snapshot_epoch_count"] = str(ERA_EPOCH_COUNT // 2)

        # set other params so that nodes won't crash
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["anticone_penalty_ratio"] = "10"
        self.conf_parameters["generate_tx_period_us"] = "100000"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"

        # make sure GC is run often
        self.conf_parameters["block_cache_gc_period_ms"] = "10"

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(ARCHIVE_NODE, ["--archive"])
        self.start_node(FULL_NODE, ["--full"], phase_to_wait=None)

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[ARCHIVE_NODE] = RpcClient(self.nodes[ARCHIVE_NODE])
        self.rpc[FULL_NODE] = RpcClient(self.nodes[FULL_NODE])

        # connect archive nodes, wait for phase changes to complete
        connect_nodes(self.nodes, ARCHIVE_NODE, FULL_NODE)

        self.nodes[ARCHIVE_NODE].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULL_NODE].wait_for_phase(["NormalSyncPhase"])

    def run_test(self):
        num_block = 10 * ERA_EPOCH_COUNT

        self.log.info(f"generating {num_block} blocks...")
        self.rpc[ARCHIVE_NODE].generate_blocks(num_block)

        # make sure blocks are synced and GC has enough time
        sync_blocks(self.nodes)
        time.sleep(1)

        # under these parameters, checkpoints are formed after 4 eras
        # we expect full nodes to keep the last 4 eras only
        self.log.info(f"checking deleted blocks...")

        for epoch in range(0, 6 * ERA_EPOCH_COUNT):
            archive_block = self.rpc[ARCHIVE_NODE].block_by_epoch(hex(epoch), include_txs=True)
            assert(archive_block != None)

            full_block = self.rpc[FULL_NODE].block_by_epoch(hex(epoch), include_txs=True)
            assert_equal(full_block, None)

        self.log.info(f"checking existing blocks...")

        for epoch in range(6 * ERA_EPOCH_COUNT, 10 * ERA_EPOCH_COUNT):
            archive_block = self.rpc[ARCHIVE_NODE].block_by_epoch(hex(epoch), include_txs=True)
            assert(archive_block != None)

            full_block = self.rpc[FULL_NODE].block_by_epoch(hex(epoch), include_txs=True)
            assert_equal(full_block, archive_block)

        self.log.info("Pass")

if __name__ == "__main__":
    FullNodeRemoveOldErasTest().main()
