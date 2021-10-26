#!/usr/bin/env python3
"""An example functional test
"""
import eth_utils
import time

from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.util import *


CHAIN_LEN = 1000


class PosForkAttackTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 - 1)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'

    def run_test(self):
        client = RpcClient(self.nodes[0])
        blocks = client.generate_empty_blocks(CHAIN_LEN)
        wait_until(lambda: client.pos_status()["latestVoted"] is not None)
        wait_until(lambda: int(client.pos_status()["pivotDecision"], 0) >= CHAIN_LEN / 2)
        assert_equal(client.block_by_epoch(int_to_hex(CHAIN_LEN / 2 + 1)), blocks[CHAIN_LEN / 2])
        fork_parent = blocks[CHAIN_LEN / 2 - 1]
        for _ in range(2 * CHAIN_LEN):
            fork_parent = client.generate_block_with_parent(fork_parent)
        assert_equal(client.block_by_epoch(int_to_hex(CHAIN_LEN / 2 + 1)), blocks[CHAIN_LEN / 2])
        exit()
        

if __name__ == '__main__':
    PosForkAttackTest().main()
