#!/usr/bin/env python3
"""An example functional test
"""

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        genesis = self.nodes[0].best_block_hash()
        self.log.info(genesis)

        self.nodes[0].test_generateEmptyBlocks(1)
        assert (self.nodes[0].test_getBlockCount() == 2)
        besthash = self.nodes[0].best_block_hash()

        self.nodes[1].test_generateEmptyBlocks(2)
        assert (self.nodes[1].test_getBlockCount() == 3)

        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes[0:2])
        assert (self.nodes[0].test_getBlockCount() == 4)

        self.nodes[0].test_generateEmptyBlocks(1)
        self.nodes[1].test_generateEmptyBlocks(1)
        sync_blocks(self.nodes[0:2])
        assert (self.nodes[0].test_getBlockCount() == 6)
        assert (self.nodes[1].test_getBlockCount() == 6)


if __name__ == '__main__':
    ExampleTest().main()
