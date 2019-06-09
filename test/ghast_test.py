#!/usr/bin/env python3
"""An example functional test
"""

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from conflux.rpc import RpcClient

INITIAL_DIFFICULTY = 2000

class GHASTTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.conf_parameters["adaptive_weight_beta"] = 1
        self.conf_parameters["initial_difficulty"] = INITIAL_DIFFICULTY

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        client0 = RpcClient(self.nodes[0])
        genesis = client0.best_block_hash()
        # print(client0.block_by_hash(genesis))

        a = self.nodes[0].generatefixedblock(genesis, [], 0, False, INITIAL_DIFFICULTY)
        block_a = client0.block_by_hash(a)
        assert(block_a['stable'] == True)
        b = self.nodes[0].generatefixedblock(a, [], 0, False, INITIAL_DIFFICULTY)
        c = self.nodes[0].generatefixedblock(genesis, [], 0, False, INITIAL_DIFFICULTY)
        d = self.nodes[0].generatefixedblock(c, [], 0, False, INITIAL_DIFFICULTY)
        if a > c:
            e = self.nodes[0].generatefixedblock(b, [d], 0, True, INITIAL_DIFFICULTY)
        else:
            e = self.nodes[0].generatefixedblock(d, [b], 0, True, INITIAL_DIFFICULTY)
        block_e = client0.block_by_hash(e)
        assert(block_e['stable'] == False)

if __name__ == '__main__':
    GHASTTest().main()
