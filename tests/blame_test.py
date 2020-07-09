#!/usr/bin/env python3
"""An example functional test
"""

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from conflux.rpc import RpcClient

class BlameTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        time.sleep(7)
        client0 = RpcClient(self.nodes[0])
        client1 = RpcClient(self.nodes[1])
        genesis = self.nodes[0].best_block_hash()
        self.log.info(genesis)

        blame_info = {}
        blame_info['blame'] = "0x1"
        blame_info['deferredStateRoot'] = "0x1111111111111111111111111111111111111111111111111111111111111111"

        self.nodes[0].test_generateblockwithblameinfo(1, 0, blame_info)
        h = self.nodes[0].generate_empty_blocks(1)
        hash_a = h[0]
        block_a = client0.block_by_hash(hash_a)
        assert(block_a['blame'] == "0x1")
        h = self.nodes[0].generate_empty_blocks(1)
        hash_b = h[0]
        block_b = client0.block_by_hash(hash_b)
        assert(block_b['blame'] == "0x0")

        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes[0:2])
        block_a1 = client1.block_by_hash(hash_a)
        assert(block_a1['blame'] == "0x1")

        self.nodes[0].test_generateblockwithblameinfo(1, 0, blame_info)
        self.nodes[0].test_generateblockwithblameinfo(1, 0, blame_info)
        self.nodes[0].test_generateblockwithblameinfo(1, 0, blame_info)
        sync_blocks(self.nodes[0:2])
        h = self.nodes[1].generate_empty_blocks(1)
        hash_c = h[0]
        block_c1 = client1.block_by_hash(hash_c)
        assert(block_c1['blame'] == "0x3")

if __name__ == '__main__':
    BlameTest().main()
