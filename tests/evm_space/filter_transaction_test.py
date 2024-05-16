#!/usr/bin/env python3

import os, sys
import random
import time

sys.path.insert(1, os.path.join(sys.path[0], ".."))

import asyncio

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, wait_until
from base import Web3Base
from conflux.config import default_config
from web3 import Web3

FULLNODE0 = 0


class FilterTransactionTest(Web3Base):
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

        ip = self.nodes[0].ip
        port = self.nodes[0].ethrpcport
        self.w3 = Web3(Web3.HTTPProvider(f"http://{ip}:{port}/"))
        assert_equal(self.w3.isConnected(), True)

    async def run_async(self):
        client = self.rpc

        self.cfxPrivkey = default_config["GENESIS_PRI_KEY"]
        self.cfxAccount = client.GENESIS_ADDR

        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(
            self.DEFAULT_TEST_ACCOUNT_KEY
        )
        self.cross_space_transfer(self.evmAccount.address, 1 * 10**18)
        assert_equal(
            self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10**18)
        )

        # new account
        account2 = self.w3.eth.account.privateKeyToAccount(hex(random.getrandbits(256)))
        self.cross_space_transfer(account2.address, 1 * 10**18)
        assert_equal(self.nodes[0].eth_getBalance(account2.address), hex(1 * 10**18))

        # create filter
        filter = self.nodes[0].eth_newPendingTransactionFilter()
        filter_txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_txs), 0)

        # target address
        to_address = self.w3.eth.account.privateKeyToAccount(
            hex(random.getrandbits(256))
        )

        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        # create txs
        txs_size = 20
        txs = []
        for i in range(txs_size):
            signed = self.evmAccount.signTransaction(
                {
                    "to": to_address.address,
                    "value": 1,
                    "gasPrice": txs_size * 2 - i,
                    "gas": 210000,
                    "nonce": nonce,
                    "chainId": 10,
                }
            )

            return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
            txs.append(return_tx_hash.hex())
            nonce += 1

        def wait_to_pack_txs(size):
            if self.nodes[0].eth_getTransactionByHash(txs[i])["blockNumber"]:
                return True
            else:
                client.generate_block(size)

        for i in range(5):
            # query txs
            self.log.info("Pack the %d tx" % i)
            filter_txs = self.nodes[0].eth_getFilterChanges(filter)
            assert_equal(len(filter_txs), 1)
            assert_equal(filter_txs[0], txs[i])
            wait_until(lambda: wait_to_pack_txs(1))

        filter_txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_txs), 1)
        assert_equal(filter_txs[0], txs[5])

        # tx for second account
        signed = account2.signTransaction(
            {
                "to": to_address.address,
                "value": 1,
                "gasPrice": 1,
                "gas": 210000,
                "nonce": self.w3.eth.getTransactionCount(account2.address),
                "chainId": 10,
            }
        )

        tx_second_account = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        filter_txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_txs), 1)
        assert_equal(filter_txs[0], tx_second_account.hex())

        # pack all transactons
        wait_until(lambda: wait_to_pack_txs(20))

        filter_txs = self.nodes[0].eth_getFilterChanges(filter)
        assert_equal(len(filter_txs), 0)

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())


if __name__ == "__main__":
    FilterTransactionTest().main()
