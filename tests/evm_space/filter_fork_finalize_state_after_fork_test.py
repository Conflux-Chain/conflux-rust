#!/usr/bin/env python3

import os, sys, time


sys.path.insert(1, os.path.join(sys.path[0], ".."))

import asyncio
from test_framework.test_framework import DefaultConfluxTestFramework

from conflux.rpc import RpcClient
from test_framework.util import (
    assert_equal,
    sync_blocks,
)
from conflux.utils import int_to_hex
from test_framework.util import wait_until


class FilterForkTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = "120"
        self.conf_parameters["poll_lifetime_in_seconds"] = "180"
        self.conf_parameters["era_epoch_count"] = "100"

        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(
            int_to_hex(int(2**256 - 1))
        )
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["dev_snapshot_epoch_count"] = "25"
        self.conf_parameters["anticone_penalty_ratio"] = "10"
        # No auto timeout.
        self.pos_parameters["round_time_ms"] = 1000000000
        self.conf_parameters["pos_reference_enable_height"] = 10
        self.conf_parameters["cip1559_transition_height"] = 10

    async def run_async(self):
        clients = []
        for node in self.nodes:
            clients.append(RpcClient(node))
        clients[0].generate_empty_blocks(10)
        sync_blocks(self.nodes)

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

        # create filter
        filter = self.nodes[0].eth_newBlockFilter()

        blocks = clients[0].generate_empty_blocks(4)
        last_block = blocks[-1]

        # query block
        filter_blocks = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_blocks), 4)

        blocks.extend(clients[0].generate_empty_blocks(6))
        filter_blocks = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_blocks), 6)

        # create fork
        for _ in range(26):
            last_block = clients[0].generate_block_with_parent(last_block)
            blocks.append(last_block)

        chain_len = 270
        blocks.extend(clients[0].generate_empty_blocks(chain_len + 1))
        sync_blocks(self.nodes)
        pivot_decision_height = (
            (300 - int(self.conf_parameters["pos_pivot_decision_defer_epoch_count"]))
            // 60
            * 60
        )
        # generate_empty_blocks may not generate a chain if the node is slow.
        chosen_decision = clients[0].block_by_epoch(int_to_hex(pivot_decision_height))[
            "hash"
        ]
        sync_blocks(self.nodes)
        for client in clients:
            client.pos_force_sign_pivot_decision(
                chosen_decision, int_to_hex(pivot_decision_height)
            )
        time.sleep(1)

        for i in range(4):
            for client in clients:
                client.pos_proposal_timeout()
            # Wait for proposal processing
            time.sleep(0.5)
            for client in clients:
                client.pos_new_round_timeout()
            time.sleep(0.5)
            blocks.extend(clients[0].generate_blocks(1))
            sync_blocks(self.nodes)
        assert_equal(
            int(clients[0].pos_status()["pivotDecision"]["height"], 0),
            pivot_decision_height,
        )
        assert_equal(clients[0].epoch_number("latest_finalized"), pivot_decision_height)

        filter_blocks = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_blocks), 297)
        idx = len(blocks) - 5
        for i in range(296, -1, -1):
            assert_equal(filter_blocks[i], blocks[idx])
            idx -= 1

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())


if __name__ == "__main__":
    FilterForkTest().main()
