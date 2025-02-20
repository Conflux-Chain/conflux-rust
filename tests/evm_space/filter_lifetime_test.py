#!/usr/bin/env python3

import os, sys, time

sys.path.insert(1, os.path.join(sys.path[0], ".."))

import asyncio

from conflux.rpc import RpcClient
from test_framework.util import assert_equal
from base import Web3Base
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError

FULLNODE0 = 0


class FilterLifetimeTest(Web3Base):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = "200"
        self.conf_parameters["poll_lifetime_in_seconds"] = "10"

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])

    async def run_async(self):
        # filter not exist
        try:
            self.nodes[0].eth_getFilterChanges("0x70ab3983392f45393c624f8e95a2dee4")
        except ReceivedErrorResponseError as e:
            assert_equal(e.response.message, "Filter not found")
        else:
            raise AssertionError("Expected exception")

        # filter not valid
        try:
            filter = {"toBlock": "pending"}
            self.nodes[0].eth_newFilter(filter)
        except ReceivedErrorResponseError as e:
            assert_equal(
                e.response.message, "Filter logs from pending blocks is not supported"
            )
        else:
            raise AssertionError("Expected exception")

        # create filter
        filter = self.nodes[0].eth_newFilter({})
        logs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(logs), 0)

        # filter timeout
        try:
            time.sleep(10)
            self.nodes[0].eth_getFilterChanges(filter)
        except ReceivedErrorResponseError as e:
            assert_equal(e.response.message, "Filter not found")
        else:
            raise AssertionError("Expected exception")

        filter = self.nodes[0].eth_newPendingTransactionFilter()
        txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(txs), 0)

        # unsubscribe filter
        self.nodes[0].eth_uninstallFilter(filter)
        try:
            self.nodes[0].eth_getFilterChanges(filter)
        except ReceivedErrorResponseError as e:
            assert_equal(e.response.message, "Filter not found")
        else:
            raise AssertionError("Expected exception")

    def run_test(self):
        asyncio.run(self.run_async())


if __name__ == "__main__":
    FilterLifetimeTest().main()
