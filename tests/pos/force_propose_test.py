#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils
import time
from eth_utils import encode_hex

from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.util import *


class PosForceProposeTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 - 1)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        # No auto timeout.
        self.pos_parameters["round_time_ms"] = 1000000000
        self.conf_parameters["pos_round_per_term"] = '10'

    def run_test(self):
        clients = []
        for node in self.nodes:
            clients.append(RpcClient(node))

        # Initialize pos_consensus_blocks
        for _ in range(3):
            for client in clients:
                client.pos_local_timeout()
            time.sleep(0.5)
            for client in clients:
                client.pos_new_round_timeout()
            time.sleep(0.5)
        wait_until(lambda: clients[0].pos_status() is not None)
        wait_until(lambda: clients[0].pos_status()["latestCommitted"] is not None)

        chain_len = 1000
        clients[0].generate_empty_blocks(chain_len + 1)
        pivot_decision_height = (chain_len - int(self.conf_parameters["pos_pivot_decision_defer_epoch_count"])) // 60 * 60
        # generate_empty_blocks may not generate a chain if the node is slow.
        chosen_decision = clients[0].block_by_epoch(int_to_hex(pivot_decision_height))["hash"]
        sync_blocks(self.nodes)
        for client in clients:
            client.pos_force_sign_pivot_decision(chosen_decision, int_to_hex(pivot_decision_height))
        chain2 = []
        fork_parent = encode_hex(self.nodes[0].p2p.genesis)
        for _ in range(chain_len):
            fork_parent = clients[0].generate_block_with_parent(fork_parent)
            chain2.append(fork_parent)
        sync_blocks(self.nodes)
        wrong_decision = chain2[pivot_decision_height - 1]
        # Wait for pivot decision to be received
        time.sleep(2)
        # Make node to propose a block
        for client in clients:
            client.pos_local_timeout()
        time.sleep(0.5)
        for client in clients:
            client.pos_new_round_timeout()
        time.sleep(0.5)
        print(clients[0].pos_get_chosen_proposal())

        future_decision = clients[0].pos_get_chosen_proposal()["pivotDecision"]["blockHash"]
        assert_equal(future_decision, chosen_decision)
        assert_equal(int(clients[0].pos_status()["pivotDecision"]["height"], 0),  0)
        parent = wrong_decision
        for _ in range(chain_len):
            parent = clients[0].generate_block_with_parent(parent)
        sync_blocks(self.nodes)
        assert_equal(clients[0].block_by_epoch(int_to_hex(pivot_decision_height))["hash"], wrong_decision)
        for i in range(3):
            for client in clients:
                client.pos_proposal_timeout()
            # Wait for proposal processing
            time.sleep(0.5)
            for client in clients:
                client.pos_new_round_timeout()
            time.sleep(0.5)
            clients[0].generate_empty_blocks(1)
            sync_blocks(self.nodes)
        wait_until(lambda: int(clients[0].pos_status()["pivotDecision"]["height"], 0) > 0)
        # Make new pos block referred and processed
        assert_equal(clients[0].block_by_epoch(int_to_hex(pivot_decision_height))["hash"], chosen_decision)
        b = clients[0].generate_empty_blocks(1)
        assert_equal(int(clients[0].block_by_hash(b[0])["blame"], 0), 0)


if __name__ == '__main__':
    PosForceProposeTest().main()
