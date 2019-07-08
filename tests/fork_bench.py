#!/usr/bin/env python3
from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt

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
        self.num_nodes = 1
        self.conf_parameters["log_level"] = "\"debug\""

    def setup_network(self):
        self.setup_nodes()
        start_p2p_connection(self.nodes)

    def run_test(self):
        block_number = 8000

        client = RpcClient(self.nodes[0])
        start = time.time()
        genesis = client.best_block_hash()
        parent = genesis
        # generate main chain
        for i in range(block_number):
            parent = client.generate_block_with_parent(parent, referee=[])
            if i % 100 == 0:
                self.log.info("generate %d blocks", i)
        prev_end = parent
        now = time.time()
        self.log.info("Time to process main chain of %d blocks: %f", block_number, now - start)
        start = now
        # process fork
        parent = genesis
        for i in range(block_number + 1):
            parent = client.generate_block_with_parent(parent, referee=[])
            self.log.debug("block hash: %s", parent)
            if i % 100 == 0:
                self.log.info("generate %d blocks", i)
        now = time.time()
        self.log.info("Time to process fork of %d blocks: %f", block_number + 1, now - start)
        # switch back to main chain
        parent = prev_end
        start = time.time()
        for i in range(2):
            parent = client.generate_block_with_parent(parent, referee=[])
        now = time.time()
        self.log.info("Time to switch back %f", now - start)


if __name__ == "__main__":
    P2PTest().main()
