#!/usr/bin/env python3
from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt

from conflux import utils
from conflux.utils import encode_hex, bytes_to_int, privtoaddr, parse_as_int
from test_framework.blocktools import create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 16
        self.rpc_timewait = 100000

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        block_number = 4000

        for i in range(1, block_number):
            chosen_peer = random.randint(0, self.num_nodes - 1)
            block_hash = self.nodes[chosen_peer].generate(1, 0)
            self.log.info("%d generate block %s", chosen_peer, block_hash)
            time.sleep(random.random()/12)
        wait_for_block_count(self.nodes[0], block_number)
        sync_blocks(self.nodes, timeout=30)
        self.log.info("Pass")


if __name__ == "__main__":
    P2PTest().main()
