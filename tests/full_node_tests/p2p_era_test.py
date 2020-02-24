#!/usr/bin/env python3
import sys, os
from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt

sys.path.insert(1, os.path.dirname(sys.path[0]))

from conflux import utils
from conflux.rpc import RpcClient
from conflux.utils import encode_hex, bytes_to_int, privtoaddr, parse_as_int
from test_framework.blocktools import create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 8
        self.conf_parameters["generate_tx"] = "true"
        # Every node generates 1 tx every second
        self.conf_parameters["generate_tx_period_us"] = "100000"
        self.conf_parameters["log_level"] = "\"debug\""
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["era_epoch_count"] = "100"
        self.conf_parameters["dev_snapshot_epoch_count"] = "50"

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0)
        for i in range(1, self.num_nodes):
            self.start_node(i, extra_args=["--full"], phase_to_wait=None)

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        block_number = 2000

        # Setup balance for each node
        client = RpcClient(self.nodes[0])
        for i in range(self.num_nodes):
            pub_key = self.nodes[i].key
            addr = self.nodes[i].addr
            self.log.info("%d has addr=%s pubkey=%s", i, encode_hex(addr), pub_key)
            tx = client.new_tx(value=int(default_config["TOTAL_COIN"]/self.num_nodes) - 21000, receiver=encode_hex(addr), nonce=i)
            client.send_tx(tx)
        for i in range(1, block_number):
            chosen_peer = random.randint(0, self.num_nodes - 1)
            if random.random() <= 0.01 and chosen_peer != 0:
                self.log.info("stop %s", chosen_peer)
                self.stop_node(chosen_peer)
                self.start_node(chosen_peer, wait_time=120, phase_to_wait=("NormalSyncPhase"))
            self.log.debug("%d try to generate", chosen_peer)
            block_hash = RpcClient(self.nodes[chosen_peer]).generate_block(random.randint(10, 100))
            self.log.info("%d generate block %s", chosen_peer, block_hash)
            time.sleep(random.random()/15)
        self.log.info("sync blocks")
        for i in range(1, self.num_nodes):
            self.nodes[i].expireblockgc(1000000)
        sync_blocks(self.nodes, timeout=120, sync_count=False)
        self.log.info("block count:%d", self.nodes[0].getblockcount())
        hasha = self.nodes[0].best_block_hash()
        block_a = client.block_by_hash(hasha)
        self.log.info("Final height = %s", block_a['height'])
        self.log.info("Pass")


if __name__ == "__main__":
    P2PTest().main()
