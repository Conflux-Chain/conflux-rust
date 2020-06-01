#!/usr/bin/env python3

import random
import threading
import time

from conflux.rpc import RpcClient
from test_framework.blocktools import wait_for_account_stable, wait_for_initial_nonce_for_privkey
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.util import assert_greater_than_or_equal, assert_equal, assert_is_hash_string, sync_blocks

class Account:
    def __init__(self, address:str, priv_key:bytes, balance:int, nonce:int=0):
        self.address = address
        self.priv_key = priv_key
        self.balance = balance
        self.nonce = nonce
        self.last_tx_hash = None

class TxConsistencyTest(DefaultConfluxTestFramework):
    def run_test(self):
        self.test(10, 100, 1000)

    def test(self, num_senders, num_receivers, num_txs):
        self.log.debug("Initializing {} senders".format(num_senders))
        senders = self.init_senders(num_senders)

        self.log.debug("Initializing {} receivers".format(num_receivers))
        receivers = self.init_receivers(num_receivers)

        self.log.info("begin to send {} txs to nodes and generate blocks ...".format(num_txs))
        txs = self.send_txs_async(senders, receivers, num_txs)

        # generate blocks to pack txs
        self.log.info("continue to generate blocks to pack all transactions ...")
        client = RpcClient(self.nodes[0])
        retry = num_txs
        for sender in senders:
            while True:
                receipt = client.get_transaction_receipt(sender.last_tx_hash)
                if receipt is not None:
                    break

                assert retry > 0, "some tx not stated yet even after {} retries".format(num_txs)
                retry -= 1

                self.generate_block(num_txs)
                time.sleep(0.5)

        # After having optimistic execution, get_receipts may get receipts with not deferred block, these extra blocks
        # ensure that later get_balance can get correct executed balance for all transactions
        for _ in range(5):
            client.generate_block()

        self.log.info("sync up blocks among nodes ...")
        sync_blocks(self.nodes)

        # check DAG
        self.log.info("begin to validate DAG for all nodes ...")
        self.check_with_rpc(client.epoch_number)
        self.check_with_rpc(client.best_block_hash)
        self.check_with_rpc(client.gas_price)
        self.check_with_rpc(client.chain, True)

        # check receipt
        self.log.info("begin to validate transaction receipts ...")
        for idx in range(self.num_nodes):
            node_client = RpcClient(self.nodes[idx])

            for tx_hash in [sent_tx.hash_hex() for sent_tx in txs]:
                receipt = node_client.get_transaction_receipt(tx_hash)
                assert_equal(receipt is None, False)

        # check balance and nonce for all accounts
        self.log.info("begin to validate balance and nonce ...")
        all_accounts = list(senders)
        all_accounts.extend(receivers)
        for idx in range(self.num_nodes):
            self.log.debug("validate for node %d", idx)
            node_client = RpcClient(self.nodes[idx])
            for account in all_accounts:
                assert_equal(node_client.get_balance(account.address), account.balance)
            for account in senders:
                assert_equal(node_client.get_nonce(account.address), account.nonce)

    def init_senders(self, num_accounts):
        accounts = []

        client = RpcClient(self.nodes[0])
        init_balance = int(client.GENESIS_ORIGIN_COIN *0.9 / num_accounts)
        assert_greater_than_or_equal(client.GENESIS_ORIGIN_COIN, num_accounts * (init_balance + client.DEFAULT_TX_FEE))
        
        for _ in range(num_accounts):
            to, priv_key = client.rand_account()
            tx = client.new_tx(receiver=to, value=init_balance)
            client.send_tx(tx, True)
            accounts.append(Account(to, priv_key, init_balance))
        # Ensure accounts have stable start nonce
        client.generate_blocks(10)
        wait_for_account_stable()
        for account in accounts:
            account.nonce = wait_for_initial_nonce_for_privkey(self.nodes[0], account.priv_key)
        return accounts

    def init_receivers(self, num_accounts):
        accounts = []
        client = RpcClient(self.nodes[0])
        
        for _ in range(num_accounts):
            accounts.append(Account(client.rand_addr(), None, 0))

        return accounts

    # send tx to random node, and generate blocks on some nodes parallelly
    def send_txs_async(self, senders, receivers, num_txs):
        txs = []

        for i in range(num_txs):
            sender = senders[random.randint(0, len(senders) - 1)]
            receiver = receivers[random.randint(0, len(receivers) - 1)]

            self.log.debug("send transaction_{}: from = {}, nonce = {}, to = {}".format(
                i, sender.address, sender.nonce, receiver.address
            ))

            tx = self.send_tx(sender, receiver)
            txs.append(tx)

            if (i + 1) % (num_txs // 10) == 0:
                self.generate_block(num_txs)

        return txs

    def sample_node_indices(self):
        ratio = random.randint(1, 10)
        sample = 1
        
        if ratio > 8:
            sample = 3
        elif ratio > 5:
            sample = 2
        
        assert_greater_than_or_equal(self.num_nodes, sample)

        indices = list(range(self.num_nodes))
        return random.sample(indices, sample)

    # randomly select N nodes to send tx.
    def send_tx(self, sender: Account, receiver: Account):
        client = RpcClient(self.nodes[0])
        tx = client.new_tx(sender.address, receiver.address, sender.nonce, value=9000, priv_key=sender.priv_key)

        def ensure_send_tx(node, tx):
            tx_hash = RpcClient(node).send_tx(tx)
            assert tx_hash is not None, "failed to send tx"

        threads = []
        for idx in self.sample_node_indices():
            t = threading.Thread(target=ensure_send_tx, args=(self.nodes[idx], tx), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        sender.balance -= 30000
        sender.nonce += 1
        sender.last_tx_hash = tx.hash_hex()
        receiver.balance += 9000

        return tx

    # randomly select N nodes to generate block parallelly.
    def generate_block(self, num_tx):
        threads = []

        def ensure_generate_block(node, txs):
            block_hash = RpcClient(node).generate_block(txs)
            assert_is_hash_string(block_hash)
        
        for idx in self.sample_node_indices():
            t = threading.Thread(target=ensure_generate_block, args=(self.nodes[idx], num_tx), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def check_with_rpc(self, client_rpc, collection_result=False):
        expected_value = client_rpc()

        if collection_result:
            self.log.debug("RPC: API = {}".format(client_rpc.__name__))
            self.log.debug(expected_value)

        for idx in range(self.num_nodes):
            client = RpcClient(self.nodes[idx])
            for name in dir(client):
                if name == client_rpc.__name__:
                    value = getattr(client, name)()
                    assert_equal(value, expected_value)

        if collection_result:
            self.log.info("check RPC: API = {}, Len = {}".format(client_rpc.__name__, len(expected_value)))
        else:
            self.log.info("check RPC: API = {}, Result = {}".format(client_rpc.__name__, expected_value))

if __name__ == "__main__":
    TxConsistencyTest().main()