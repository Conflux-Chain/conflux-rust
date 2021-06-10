#!/usr/bin/env python3
"""An example functional test
"""
import time

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes(is_consortium=True)

    def run_test(self):
        time.sleep(2)
        genesis = self.nodes[0].best_block_hash()
        self.log.info(genesis)

        self.nodes[0].generate_empty_blocks(1)
        assert (self.nodes[0].getblockcount() == 2)

        latest_pos_ref = self.latest_pos_ref()
        for _ in range(10):
            # Generate enough PoW block for PoS to progress
            self.nodes[0].generate_empty_blocks(600)
            # Leave some time for PoS to reach consensus
            time.sleep(1)
            self.nodes[0].generate_empty_blocks(1)
            new_pos_ref = self.latest_pos_ref()
            assert_ne(latest_pos_ref, new_pos_ref)
        # assert (self.nodes[0].getblockcount() == 6002)

    def latest_pos_ref(self):
        best_hash = self.nodes[0].best_block_hash()
        block = self.nodes[0].cfx_getBlockByHash(best_hash, False)
        return block["posReference"]

if __name__ == '__main__':
    ExampleTest().main()
