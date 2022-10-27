#!/usr/bin/env python3

import os, sys

sys.path.insert(1, os.path.join(sys.path[0], ".."))

import asyncio

from conflux.rpc import RpcClient
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
    sync_blocks,
)
from base import Web3Base

FULLNODE0 = 0
FULLNODE1 = 1


class FilterBlockTest(Web3Base):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = "120"
        self.conf_parameters["poll_lifetime_in_seconds"] = "180"
        self.conf_parameters["era_epoch_count"] = "100"

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])

        # connect nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    async def run_async(self):
        client1 = self.rpc[FULLNODE0]
        client2 = self.rpc[FULLNODE1]

        # create filter
        filter = self.nodes[0].eth_newBlockFilter()

        blocks = self.nodes[0].generate_empty_blocks(4)

        # query block
        filter_blocks = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_blocks), 0)

        # generate common blocks
        blocks.extend(self.nodes[0].generate_empty_blocks(20))
        sync_blocks(self.nodes[0:2])

        e1 = client1.epoch_number()
        e2 = client2.epoch_number()
        self.log.info("Node 1 epoch {}".format(e1))
        self.log.info("Node 2 epoch {}".format(e2))

        filter_blocks = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_blocks), 20)
        idx = len(blocks) - 5
        for i in range(19, -1, -1):
            assert_equal(filter_blocks[i], blocks[idx])
            idx -= 1

        # Disconnect nodes
        disconnect_nodes(self.nodes, 0, 1)

        # blocks in node1
        blocks.extend(self.nodes[0].generate_empty_blocks(6))

        filter_blocks = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_blocks), 6)

        idx = len(blocks) - 5
        for i in range(5, -1, -1):
            assert_equal(filter_blocks[i], blocks[idx])
            idx -= 1

        blocks.extend(self.nodes[0].generate_empty_blocks(1))
        filter_blocks = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_blocks), 1)
        assert_equal(filter_blocks[0], blocks[len(blocks) - 5])

        # blocks in node2
        blocks.extend(self.nodes[1].generate_empty_blocks(12))

        # re-org
        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes[0:2])

        filter_blocks = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_blocks), 8)
        idx = len(blocks) - 5
        for i in range(7, -1, -1):
            assert_equal(filter_blocks[i], blocks[idx])
            idx -= 1

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())


if __name__ == "__main__":
    FilterBlockTest().main()
