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
        self.pos_parameters["round_time_ms"] = 1000000000

    def run_test(self):
        clients = []
        for node in self.nodes:
            clients.append(RpcClient(node))

        blocks = clients[0].generate_empty_blocks(CHAIN_LEN)
        sync_blocks(self.nodes)
        last_block = clients[0].block_by_epoch(int_to_hex(CHAIN_LEN // 60 * 60))
        clients[0].pos_force_sign_pivot_decision(last_block["hash"], last_block["height"])
        clients[1].pos_force_sign_pivot_decision(last_block["hash"], last_block["height"])

        # generate pos blocks to confirm the pivot decision
        for client in clients:
            client.pos_local_timeout()
        # Wait for force signed transactions to be received by each other
        time.sleep(3)
        for client in clients:
            client.pos_new_round_timeout()
        time.sleep(1)
        for _ in range(3):
            for client in clients:
                client.pos_proposal_timeout()
            time.sleep(1)
            for client in clients:
                client.pos_new_round_timeout()
            time.sleep(1)

        assert clients[0].pos_status()["latestVoted"] is not None
        assert int(clients[0].pos_status()["pivotDecision"]["height"], 0) >= CHAIN_LEN // 2
        fork_pivot_block = clients[0].block_by_epoch(int_to_hex(CHAIN_LEN // 2 + 1))
        assert_equal(fork_pivot_block["posReference"], "0x"+"0"*64)

        # generate a block to refer new pos blocks.
        clients[0].generate_empty_blocks(1)

        # Generate blocks with the latest pos_reference. They will be partially invalid.
        fork_parent = fork_pivot_block["parentHash"]
        for _ in range(2 * CHAIN_LEN):
            fork_parent = clients[0].generate_block_with_parent(fork_parent)
        # generate blocks to activate these partially invalid blocks.
        clients[0].generate_empty_blocks(100)
        assert_equal(clients[0].block_by_epoch(int_to_hex(CHAIN_LEN // 2 + 1))["hash"], fork_pivot_block["hash"])

        # Generate blocks with old pos_reference. They are valid but in a fork before the latest pivot decision.
        fork_parent = blocks[CHAIN_LEN // 2 - 1]
        for _ in range(2 * CHAIN_LEN):
            fork_parent = clients[0].generate_block_with_parent(fork_parent, pos_reference="0x"+"0"*64)
        assert_equal(clients[0].block_by_epoch(int_to_hex(CHAIN_LEN // 2 + 1))["hash"], fork_pivot_block["hash"])
        

if __name__ == '__main__':
    PosForkAttackTest().main()
