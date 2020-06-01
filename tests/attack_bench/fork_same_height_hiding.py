#!/usr/bin/env python3
import os, sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))


from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


'''
An attacker keeps mining with the same parent block and release them at once.
'''
class SameHeightTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        attacker = RpcClient(self.nodes[0])
        victim = RpcClient(self.nodes[1])
        n_generate_batch = 1000
        n_attack_blocks = 15000
        self.log.info(f"Attacker start to prepare {n_attack_blocks} blocks")
        fork_point = attacker.generate_empty_blocks(1000)[-1]
        for _ in range(n_attack_blocks):
            attacker.generate_block_with_parent(fork_point)
        self.log.info("Honest node generate")
        for _ in range(int(20000/n_generate_batch)):
            batch_generate(victim, n_generate_batch, self.log)
        connect_nodes(self.nodes, 0, 1)
        self.log.info("Nodes connected")
        for _ in range(1000):
            batch_generate(victim, n_generate_batch, self.log)


def batch_generate(node, n_blocks, log):
    start = time.time()
    node.generate_empty_blocks(n_blocks)
    elapsed = time.time() - start
    log.info(f"process {n_blocks} blocks with {elapsed} seconds")


if __name__ == '__main__':
    SameHeightTest().main()
