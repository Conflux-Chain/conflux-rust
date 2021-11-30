#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

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
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["pos_round_per_term"] = '10'

    def run_test(self):
        client = RpcClient(self.nodes[0])
        client2 = RpcClient(self.nodes[1])
        blocks = client.generate_empty_blocks(CHAIN_LEN)
        sync_blocks(self.nodes)
        last_block = client.block_by_epoch(int_to_hex(CHAIN_LEN // 60 * 60))
        client.pos_force_sign_pivot_decision(last_block["hash"], last_block["height"])
        client2.pos_force_sign_pivot_decision(last_block["hash"], last_block["height"])
        wait_until(lambda: client.pos_status()["latestVoted"] is not None)
        wait_until(lambda: int(client.pos_status()["pivotDecision"]["height"], 0) >= CHAIN_LEN // 2)
        # generate a block to refer new pos blocks.
        client.generate_empty_blocks(1)
        fork_pivot_block = client.block_by_epoch(int_to_hex(CHAIN_LEN // 2 + 1))
        assert_equal(fork_pivot_block["hash"], blocks[CHAIN_LEN // 2])
        assert_equal(fork_pivot_block["posReference"], "0x"+"0"*64)

        # Generate blocks with the latest pos_reference. They will be partially invalid.
        fork_parent = blocks[CHAIN_LEN // 2 - 1]
        for _ in range(2 * CHAIN_LEN):
            fork_parent = client.generate_block_with_parent(fork_parent)
        # generate blocks to activate these partially invalid blocks.
        client.generate_empty_blocks(100)
        assert_equal(client.block_by_epoch(int_to_hex(CHAIN_LEN // 2 + 1))["hash"], blocks[CHAIN_LEN // 2])

        # Generate blocks with old pos_reference. They are valid but in a fork before the latest pivot decision.
        fork_parent = blocks[CHAIN_LEN // 2 - 1]
        for _ in range(2 * CHAIN_LEN):
            fork_parent = client.generate_block_with_parent(fork_parent, pos_reference="0x"+"0"*64)
        assert_equal(client.block_by_epoch(int_to_hex(CHAIN_LEN // 2 + 1))["hash"], blocks[CHAIN_LEN // 2])
        

if __name__ == '__main__':
    PosForkAttackTest().main()
