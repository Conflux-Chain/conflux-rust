#!/usr/bin/env python3

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

class Issue2235Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

    def run_test(self):

        #                      ---
        #                  .- | A | <--- ...
        #           ---    |   ---
        # ... <--- | 0 | <-*
        #           ---    |   ---
        #                  .- | B | <--- ...
        #                      ---

        block_number_0 = int(self.rpc.block_by_epoch("latest_mined")['epochNumber'], 0)
        block_0 = self.rpc.block_by_epoch("latest_mined")['hash']

        block_a = self.rpc.generate_custom_block(parent_hash = block_0, referee = [], txs = [])
        block_b = self.rpc.generate_custom_block(parent_hash = block_0, referee = [], txs = [])

        # create pivot chain from 'A', make sure 'A' is executed
        parent_hash = block_a

        for _ in range(5):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        block_after_0 = self.rpc.block_by_block_number(hex(block_number_0 + 1))["hash"]
        assert_equal(block_a, block_after_0)

        # switch pivot chain to 'B', make sure 'B' is executed
        parent_hash = block_b

        for _ in range(6):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        block_after_0 = self.rpc.block_by_block_number(hex(block_number_0 + 1))["hash"]
        assert_equal(block_b, block_after_0)

        # switch pivot chain back to 'A', make sure 'A' is executed
        parent_hash = block_a

        for _ in range(7):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        block_after_0 = self.rpc.block_by_block_number(hex(block_number_0 + 1))["hash"]
        assert_equal(block_a, block_after_0) # <<< (#2235)

        self.log.info("Pass")

if __name__ == "__main__":
    Issue2235Test().main()
