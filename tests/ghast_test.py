#!/usr/bin/env python3
"""An example functional test
"""

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from conflux.rpc import RpcClient

TIMER_RATIO = 3
TIMER_BETA = 20
INITIAL_DIFFICULTY = 1000

class GHASTTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = TIMER_RATIO
        self.conf_parameters["timer_chain_beta"] = TIMER_BETA
        self.conf_parameters["initial_difficulty"] = INITIAL_DIFFICULTY

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        client0 = RpcClient(self.nodes[0])
        client1 = RpcClient(self.nodes[1])
        genesis = client0.best_block_hash()

        self.log.info("Generating two initial blocks")

        a1 = client0.generate_block()
        a2 = client0.generate_block()
        block_a2 = client0.block_by_hash(a2)
        assert(int(block_a2['height'], 16) == 2)

        self.log.info("Generating two invalid blocks")

        invalid = self.nodes[0].generatefixedblock(genesis, [a2], 0, False, INITIAL_DIFFICULTY)
        invalid2 = self.nodes[0].generatefixedblock(a2, [invalid], 0, False, INITIAL_DIFFICULTY)

        self.log.info("Sync two nodes")
        connect_nodes(self.nodes, 0, 1)
        wait_until(lambda: self.nodes[1].getblockcount() >= 3, timeout = 10)
        self.log.info("Node0 block count " + str(self.nodes[0].getblockcount()))
        self.log.info("Node1 block count " + str(self.nodes[1].getblockcount()))

        self.log.info("Generating a block without referencing partial invalid blocks")

        b1 = client1.generate_block()
        block_b1 = client1.block_by_hash(b1)
        assert(block_b1['parentHash'] == a2)
        assert(len(block_b1['refereeHashes']) == 0)

        self.log.info("Sync two nodes")
        connect_nodes(self.nodes, 1, 0)
        wait_until(lambda: self.nodes[0].getblockcount() >= 6, timeout = 40)
        wait_until(lambda: self.nodes[1].getblockcount() >= 4, timeout = 40)

        timer_cnt = 0
        diff = int(block_b1['difficulty'], 16)
        pow_qual = int(block_b1['powQuality'], 16)
        if diff * TIMER_RATIO <= pow_qual:
            timer_cnt = 1

        self.log.info("Start timer tick " + str(timer_cnt))

        while timer_cnt < TIMER_BETA:
            a = client0.generate_block()
            self.log.info("Generated a block " + a)
            block_a = client0.block_by_hash(a)
            assert(len(block_a['refereeHashes']) == 0)
            diff = int(block_a['difficulty'], 16)
            pow_qual = int(block_a['powQuality'], 16)
            if diff * TIMER_RATIO <= pow_qual:
                timer_cnt += 1
                self.log.info("Timer increased to " + str(timer_cnt))

        self.log.info("Sync two nodes")
        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes)

        self.log.info("Node1 generating a block to reference two partial invalid blocks")

        b2 = client1.generate_block()
        block_b2 = client1.block_by_hash(b2)
        assert(len(block_b2['refereeHashes']) > 0)
        assert(block_b2['refereeHashes'][0] == invalid2)

        self.log.info("Pass!")

if __name__ == '__main__':
    GHASTTest().main()
