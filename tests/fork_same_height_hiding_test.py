#!/usr/bin/env python3
import os, sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))


from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
import time

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
        n_attack_blocks = 1000
        self.log.info(f"Attacker start to prepare {n_attack_blocks} blocks")
        fork_point = attacker.generate_empty_blocks(1000)[-1]
        for _ in range(n_attack_blocks):
            attacker.generate_block_with_parent(fork_point)
        attacker_cnt = self.nodes[0].getblockcount()
        self.log.info("Attacker block count:" + str(attacker_cnt))
        self.log.info("Honest node generate")
        for _ in range(int(2000/n_generate_batch)):
            batch_generate(victim, n_generate_batch, self.log)
            cnt = self.nodes[1].getblockcount()
            self.log.info("Honest block count: " + str(cnt))
        connect_nodes(self.nodes, 0, 1)
        self.log.info("Nodes connected")
        pass_test = False
        target = 4001
        for _ in range(200):
            self.nodes[1].generate_empty_blocks(1)
            target += 1
            cnt = self.nodes[1].getblockcount()
            self.log.info("Honest block count: " + str(cnt))
            if cnt == target:
                pass_test = True
                break
            time.sleep(1)
        assert(pass_test)
        self.log.info("Pass!")


def batch_generate(node, n_blocks, log):
    start = time.time()
    node.generate_empty_blocks(n_blocks)
    elapsed = time.time() - start
    log.info(f"process {n_blocks} blocks with {elapsed} seconds")


if __name__ == '__main__':
    SameHeightTest().main()
