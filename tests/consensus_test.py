#!/usr/bin/env python3
"""An example functional test
"""

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class FixedGenerateTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        time.sleep(7)
        genesis = self.nodes[0].getbestblockhash()
        self.log.info(genesis)

        blocks = self.nodes[0].generate(3, 0)
        assert (self.nodes[0].getblockcount() == 4)
        besthash0 = self.nodes[0].getbestblockhash()
        assert (besthash0 == blocks[2])
        self.log.info("Generate three blocks in one chain for node 0")

        blocks1 = self.nodes[1].generate(4, 0)
        assert (self.nodes[1].getblockcount() == 5)
        besthash1 = self.nodes[1].getbestblockhash()
        self.log.info("Generate four blocks in another chain for node 1")

        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes[0:2])
        assert (self.nodes[0].getblockcount() == 8)
        assert (self.nodes[0].getbestblockhash() == besthash1)
        self.log.info("Connect together now have 8 blocks in total")

        blocka = self.nodes[1].generatefixedblock(blocks[0], [], 0, False)
        blockb = self.nodes[1].generatefixedblock(blocks[0], [], 0, False)
        sync_blocks(self.nodes[0:2])
        self.log.info("Generate two more blocks on the shorter chain")
        assert (self.nodes[0].getblockcount() == 10)
        assert (self.nodes[0].getbestblockhash() == besthash0)
        self.log.info("Pivot chain switched!")

        blocka = self.nodes[1].generatefixedblock(blocks1[0], [besthash0], 0, False)
        blockb = self.nodes[1].generatefixedblock(blocks1[0], [besthash0], 0, False)
        sync_blocks(self.nodes[0:2])
        assert (self.nodes[0].getbestblockhash() == besthash0)
        assert (self.nodes[1].getbestblockhash() == besthash0)
        self.log.info("Partially invalid blocks do not affect the pivot chain")

        blocka = self.nodes[1].generatefixedblock(blocks1[0], [], 0, False)
        blockb = self.nodes[1].generatefixedblock(blocks1[0], [], 0, False)
        sync_blocks(self.nodes[0:2])
        assert (self.nodes[0].getbestblockhash() == besthash1)
        assert (self.nodes[1].getbestblockhash() == besthash1)
        self.log.info("Pivot chain switched again!")

if __name__ == '__main__':
    FixedGenerateTest().main()
