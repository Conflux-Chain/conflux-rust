#!/usr/bin/env python3

from eth_utils import decode_hex, encode_hex

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys, inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

class LightSyncTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        self.add_nodes(3)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])
        self.start_node(LIGHTNODE, ["--light"], wait_for_recovery=False)

        # connect archive nodes, wait for phase changes to complete
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)
        time.sleep(3)

    def connect_light_node(self, nodes):
        for n in nodes:
            connect_nodes(self.nodes, LIGHTNODE, n)

    def disconnect_light_node(self, nodes):
        for n in nodes:
            disconnect_nodes(self.nodes, LIGHTNODE, n)

    def random_full_node(self):
        return random.randint(0, self.num_nodes - 2) # 0..1 inclusive

    def generate_blocks(self, num):
        for _ in range(num):
            chosen_peer = self.random_full_node()
            block_hash = self.nodes[chosen_peer].generate(1, 0)
            self.log.info("%s generate block %s", chosen_peer, block_hash)

    def run_test(self):
        block_batch_size = 100

        # NOTE: do not start p2p for LIGHTNODE
        start_p2p_connection(self.nodes[0 : (self.num_nodes - 1)])

        # catch up
        self.disconnect_light_node([FULLNODE0, FULLNODE1])

        self.generate_blocks(block_batch_size)
        wait_for_block_count(self.nodes[FULLNODE0], 1 * block_batch_size + 1)
        wait_for_block_count(self.nodes[FULLNODE1], 1 * block_batch_size + 1)

        self.connect_light_node([FULLNODE0, FULLNODE1])
        wait_for_block_count(self.nodes[LIGHTNODE], 1 * block_batch_size + 1)
        self.log.info("Pass 1")

        # keep up
        self.generate_blocks(block_batch_size)
        wait_for_block_count(self.nodes[FULLNODE0], 2 * block_batch_size + 1)
        wait_for_block_count(self.nodes[FULLNODE1], 2 * block_batch_size + 1)
        wait_for_block_count(self.nodes[LIGHTNODE], 2 * block_batch_size + 1)
        self.log.info("Pass 2")

        # catch up again
        self.disconnect_light_node([FULLNODE0, FULLNODE1])

        self.generate_blocks(block_batch_size)
        wait_for_block_count(self.nodes[FULLNODE0], 3 * block_batch_size + 1)
        wait_for_block_count(self.nodes[FULLNODE1], 3 * block_batch_size + 1)

        self.connect_light_node([FULLNODE0])
        wait_for_block_count(self.nodes[LIGHTNODE], 3 * block_batch_size + 1)
        self.log.info("Pass 3")


if __name__ == "__main__":
    LightSyncTest().main()
