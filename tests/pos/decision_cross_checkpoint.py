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


class PosDecisionCrossCheckpoint(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 - 1)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["era_epoch_count"] = "100"
        self.conf_parameters["dev_snapshot_epoch_count"] = "25"
        self.conf_parameters["anticone_penalty_ratio"] = "10"
        # No auto timeout.
        self.pos_parameters["round_time_ms"] = 1000000000

    def run_test(self):
        clients = []
        for node in self.nodes:
            clients.append(RpcClient(node))

        # Initialize pos_consensus_blocks
        for _ in range(4):
            for client in clients:
                client.pos_proposal_timeout()
            time.sleep(0.5)
            for client in clients:
                client.pos_new_round_timeout()
            time.sleep(0.5)
        wait_until(lambda: clients[0].pos_status() is not None)
        wait_until(lambda: clients[0].pos_status()["latestCommitted"] is not None)

        chain_len = 300
        clients[0].generate_empty_blocks(chain_len + 1)
        sync_blocks(self.nodes)
        pivot_decision_height = (chain_len - int(self.conf_parameters["pos_pivot_decision_defer_epoch_count"])) // 60 * 60
        # generate_empty_blocks may not generate a chain if the node is slow.
        chosen_decision = clients[0].block_by_epoch(int_to_hex(pivot_decision_height))["hash"]
        sync_blocks(self.nodes)
        for client in clients:
            client.pos_force_sign_pivot_decision(chosen_decision, int_to_hex(pivot_decision_height))
        time.sleep(1)

        for i in range(4):
            for client in clients:
                client.pos_proposal_timeout()
            # Wait for proposal processing
            time.sleep(0.5)
            for client in clients:
                client.pos_new_round_timeout()
            time.sleep(0.5)
            clients[0].generate_blocks(1)
            sync_blocks(self.nodes)
        assert_equal(int(clients[0].pos_status()["pivotDecision"]["height"], 0), pivot_decision_height)
        assert_equal(clients[0].epoch_number("latest_finalized"), pivot_decision_height)

        clients[0].generate_blocks(500)
        sync_blocks(self.nodes)
        # assert the previous pivot decision is before checkpoint.
        assert_greater_than(clients[0].epoch_number("latest_checkpoint"), pivot_decision_height)
        pivot_decision_height = (clients[0].epoch_number() - int(self.conf_parameters["pos_pivot_decision_defer_epoch_count"])) // 60 * 60
        chosen_decision = clients[0].block_by_epoch(int_to_hex(pivot_decision_height))["hash"]
        sync_blocks(self.nodes)
        for client in clients:
            client.pos_force_sign_pivot_decision(chosen_decision, int_to_hex(pivot_decision_height))
        time.sleep(1)
        for _ in range(4):
            for client in clients:
                client.pos_proposal_timeout()
            time.sleep(0.5)
            for client in clients:
                client.pos_new_round_timeout()
            time.sleep(0.5)
            clients[0].generate_blocks(1)
            sync_blocks(self.nodes)
        assert_equal(int(clients[0].pos_status()["pivotDecision"]["height"], 0), pivot_decision_height)
        assert_equal(clients[0].epoch_number("latest_finalized"), pivot_decision_height)


if __name__ == '__main__':
    PosDecisionCrossCheckpoint().main()
