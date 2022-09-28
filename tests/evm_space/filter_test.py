#!/usr/bin/env python3

import os, sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))

import asyncio

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, connect_nodes, disconnect_nodes, sync_blocks
from base import Web3Base

FULLNODE0 = 0
FULLNODE1 = 1

class FilterBlockTest(Web3Base):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        self.conf_parameters["poll_lifetime_in_seconds"] = '180'
        self.conf_parameters["era_epoch_count"] = "100"

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])

    async def run_async(self):
        client1 = self.rpc[FULLNODE0]

        # create filter
        filter = self.nodes[0].eth_newPendingTransactionFilter()
        txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(txs), 0)

        tx = client1.new_tx()
        tx_hash = client1.send_tx(tx)
        
        txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(txs), 0)


    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())


if __name__ == "__main__":
    FilterBlockTest().main()
