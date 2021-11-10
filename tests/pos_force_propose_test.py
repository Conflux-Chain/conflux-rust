#!/usr/bin/env python3
"""An example functional test
"""
import eth_utils
import time
from eth_utils import encode_hex

from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.util import *


class PosEquivocateVoteTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 - 1)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        # No auto timeout.
        self.pos_parameters["round_time_ms"] = 1000000000

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
        chain1 = clients[0].generate_empty_blocks(chain_len)
        pivot_decision_height = (chain_len - int(self.conf_parameters["pos_pivot_decision_defer_epoch_count"])) // 60 * 60
        pivot_decision1 = chain1[pivot_decision_height - 1]
        sync_blocks(self.nodes)
        for client in clients:
            client.pos_force_sign_pivot_decision(pivot_decision1, pivot_decision_height)
        chain2 = []
        fork_parent = encode_hex(self.nodes[0].p2p.genesis)
        for _ in range(chain_len):
            fork_parent = clients[0].generate_block_with_parent(fork_parent)
            chain2.append(fork_parent)
        sync_blocks(self.nodes)
        pivot_decision2 = chain2[pivot_decision_height - 1]
        for client in clients:
            client.pos_force_sign_pivot_decision(pivot_decision2, pivot_decision_height)
        # Wait for pivot decision to be received
        time.sleep(2)
        # Make node 0 to propose a block
        for client in clients:
            client.pos_local_timeout()
        time.sleep(0.5)
        clients[0].pos_new_round_timeout()
        time.sleep(0.5)
        print(clients[0].pos_get_chosen_proposal())
        future_decision = clients[0].pos_get_chosen_proposal()["pivotDecision"]["blockHash"]
        two_decisions = set([pivot_decision1, pivot_decision2])
        print(two_decisions, future_decision)
        two_decisions.remove(future_decision)
        assert_equal(len(two_decisions), 1)
        wrong_decision = two_decisions.pop()
        parent = wrong_decision
        for _ in range(chain_len):
            parent = clients[0].generate_block_with_parent(parent)
        sync_blocks(self.nodes)
        assert_equal(clients[0].block_by_epoch(int_to_hex(pivot_decision_height))["hash"], wrong_decision)
        for client in clients:
            client.pos_new_round_timeout()
        for _ in range(3):
            for client in clients:
                client.pos_proposal_timeout()
            # Wait for proposal processing
            time.sleep(0.5)
            for client in clients:
                client.pos_new_round_timeout()
        wait_until(lambda: int(clients[0].pos_status()["pivotDecision"]["height"], 0) > 0)
        # Make new pos block referred and processed
        clients[0].generate_empty_blocks(1)
        assert_equal(clients[0].block_by_epoch(int_to_hex(pivot_decision_height))["hash"], future_decision)


if __name__ == '__main__':
    PosEquivocateVoteTest().main()
