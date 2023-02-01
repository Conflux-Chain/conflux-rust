#!/usr/bin/env python3

import os, sys
import random
import time

sys.path.insert(1, os.path.join(sys.path[0], ".."))

import asyncio

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, wait_until
from conflux.config import default_config
from conflux.utils import priv_to_addr
import eth_utils

FULLNODE0 = 0


class FilterTransactionTest(ConfluxTestFramework):
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
        self.rpc = RpcClient(self.nodes[FULLNODE0])

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])

    async def run_async(self):
        client = self.rpc

        self.cfxPrivkey = default_config["GENESIS_PRI_KEY"]
        self.cfxAccount = client.GENESIS_ADDR

        # create filter
        filter = self.nodes[0].cfx_newPendingTransactionFilter()
        filter_txs = self.nodes[0].cfx_getFilterChanges(filter)
        assert_equal(len(filter_txs), 0)

        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))
        nonce = client.get_nonce(sender)

        # create txs
        txs_size = 20
        txs = []
        for _ in range(txs_size):
            tx = client.new_tx(
                receiver="0x00e45681ac6c53d5a40475f7526bac1fe7590fb8", nonce=nonce
            )
            assert_equal(client.send_tx(tx), tx.hash_hex())

            txs.append(tx.hash_hex())
            nonce += 1

        def wait_to_pack_txs(size):
            ret = client.get_tx(txs[i])
            if ret["status"]:
                return True
            else:
                client.generate_block(size)

        for i in range(5):
            # query txs
            self.log.info("Pack the %d tx" % i)
            filter_txs = self.nodes[0].cfx_getFilterChanges(filter)
            assert_equal(len(filter_txs), 1)
            assert_equal(filter_txs[0], txs[i])
            # wait_until(lambda: wait_to_pack_txs(1))
            client.generate_block(1)

        filter_txs = self.nodes[0].cfx_getFilterChanges(filter)
        assert_equal(len(filter_txs), 1)
        assert_equal(filter_txs[0], txs[5])

        # tx for second account
        priv_key_2 = default_config["GENESIS_PRI_KEY_2"]
        tx_second_account = client.new_tx(
            receiver="0x00e45681ac6c53d5a40475f7526bac1fe7590fb8", priv_key=priv_key_2
        )
        client.send_tx(tx_second_account)

        filter_txs = self.nodes[0].cfx_getFilterChanges(filter)
        assert_equal(len(filter_txs), 1)
        assert_equal(filter_txs[0], tx_second_account.hash_hex())

        # pack all transactons
        wait_until(lambda: wait_to_pack_txs(20))

        filter_txs = self.nodes[0].cfx_getFilterChanges(filter)
        assert_equal(len(filter_txs), 0)

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())


if __name__ == "__main__":
    FilterTransactionTest().main()
