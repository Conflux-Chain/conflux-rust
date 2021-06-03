#!/usr/bin/env python3
"""An example functional test
"""
import time

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes(is_consortium=True)

    def run_test(self):
        time.sleep(2)
        genesis = self.nodes[0].best_block_hash()
        self.log.info(genesis)

        self.nodes[0].generate_empty_blocks(1)
        assert (self.nodes[0].getblockcount() == 2)

        for _ in range(10):
            self.nodes[0].generate_empty_blocks(6000)
            time.sleep(1)
        # assert (self.nodes[0].getblockcount() == 6002)


if __name__ == '__main__':
    ExampleTest().main()
