#!/usr/bin/env python3
import sys, os
from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt

sys.path.insert(1, os.path.dirname(sys.path[0]))

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
        self.conf_parameters["generate_tx_period_us"] = "100000"
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["era_epoch_count"] = "100"
        self.conf_parameters["dev_snapshot_epoch_count"] = "25"
        self.conf_parameters["anticone_penalty_ratio"] = "10"
        # Make sure that after cleaning the local data for a node,
        # it goes through all the phases to download data as a normal node.
        self.conf_parameters["dev_allow_phase_change_without_peer"] = "false"

        self.stop_probability = 0.01
        self.clean_probability = 0.5

        self.all_nodes = list(range(0, self.num_nodes))
        self.archive_nodes = list(range(0, self.num_nodes // 2))
        self.full_nodes = list(range(self.num_nodes // 2, self.num_nodes))

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)

        # start half of the nodes as archive nodes
        for i in self.archive_nodes:
            self.start_node(i, phase_to_wait=None)

        # start half of the nodes as full nodes
        for i in self.full_nodes:
            self.start_node(i, extra_args=["--full"], phase_to_wait=None)

    def setup_network(self):
        self.setup_nodes()
        # Make all nodes fully connected, so a crashed archive node can be connected to another
        # archive node to catch up
        connect_sample_nodes(self.nodes, self.log, sample=self.num_nodes - 1)
        sync_blocks(self.nodes)
        for node in self.nodes:
            node.wait_for_recovery(["NormalSyncPhase"], 30)

    def run_test(self):
        block_number = 2000

        # Setup balance for each node
        client = RpcClient(self.nodes[0])

        for i in self.all_nodes:
            pub_key = self.nodes[i].key
            addr = self.nodes[i].addr
            self.log.info("%d has addr=%s pubkey=%s", i, encode_hex(addr), pub_key)
            tx = client.new_tx(value=int(default_config["TOTAL_COIN"]/self.num_nodes) - 21000, receiver=encode_hex(addr), nonce=i)
            client.send_tx(tx)

        for i in range(1, block_number):
            chosen_peer = random.randint(0, self.num_nodes - 1)
            self.maybe_restart_node(chosen_peer, self.stop_probability, self.clean_probability)
            self.log.debug("%d try to generate", chosen_peer)
            block_hash = RpcClient(self.nodes[chosen_peer]).generate_block(random.randint(10, 100))
            self.log.info("%d generate block %s", chosen_peer, block_hash)
            time.sleep(random.random()/15)

        self.log.info("sync blocks")

        for i in self.full_nodes:
            self.nodes[i].expireblockgc(1000000)

        sync_blocks(self.nodes, timeout=120, sync_count=False)
        self.log.info("block count:%d", self.nodes[0].getblockcount())

        hasha = self.nodes[0].best_block_hash()
        block_a = client.block_by_hash(hasha)
        self.log.info("Final height = %s", block_a['height'])
        self.log.info("Pass")


if __name__ == "__main__":
    P2PTest().main()
