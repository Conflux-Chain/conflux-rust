#!/usr/bin/env python3

import os, sys

sys.path.insert(1, os.path.join(sys.path[0], ".."))

import asyncio

from conflux.rpc import RpcClient
from test_framework.util import assert_equal
from base import Web3Base

FULLNODE0 = 0


class FilterBlockTest(Web3Base):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = "120"
        self.conf_parameters["poll_lifetime_in_seconds"] = "180"
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
        filter_txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_txs), 0)

        # create txs
        txs_size = 20
        txs = []
        nonce = 0
        for _ in range(txs_size):
            tx = client1.new_tx(nonce=nonce)
            txs.append(client1.send_tx(tx))
            nonce += 1

        # query txs
        filter_txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_txs), txs_size)
        for tx in filter_txs:
            assert tx in txs

        # generate block
        block = client1.block_by_hash(client1.generate_block(1), include_txs=True)
        assert_equal(block["transactions"][0]["hash"], txs[0])

        # generate one more tx
        tx = client1.new_tx(nonce=nonce)
        txs.append(client1.send_tx(tx))

        filter_txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_txs), 1)
        assert_equal(filter_txs[0], txs[-1])

        # pack all txs
        block = client1.block_by_hash(
            client1.generate_block(txs_size), include_txs=True
        )
        assert_equal(len(block["transactions"]), txs_size)

        filter_txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_txs), 0)

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())


if __name__ == "__main__":
    FilterBlockTest().main()
