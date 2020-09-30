#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys, time
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

class TxRelayTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])
        self.start_node(LIGHTNODE, ["--light"], phase_to_wait=None)

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])
        self.rpc[LIGHTNODE] = RpcClient(self.nodes[LIGHTNODE])

        # connect archive nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)

        # connect light node to archive nodes
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE0)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    def random_full_node(self):
        return random.randint(0, self.num_nodes - 2) # 0..1 inclusive

    def generate_correct_block(self, node=None):
        if node is None: node = self.random_full_node()
        return self.rpc[node].generate_block()

    def generate_incorrect_block(self, node=None):
        if node is None: node = self.random_full_node()

        blame_info = {}
        blame_info['blame'] = "0x1"
        blame_info['deferredStateRoot'] = "0x1111111111111111111111111111111111111111111111111111111111111111"

        return self.nodes[node].test_generateblockwithblameinfo(1, 0, blame_info)

    def run_test(self):
        num_blocks = 100
        num_txs = 20
        txs = []

        # ------------------------------------------------
        # send transactions
        self.log.info(f"Sending {num_txs} txs through the light node...")
        for nonce in range(0, num_txs):
            # generate random account and value
            receiver, _ = self.rpc[LIGHTNODE].rand_account()
            value = random.randint(1000, 100000)

            # send tx from genesis account
            tx = self.rpc[LIGHTNODE].new_tx(receiver=receiver, value=value, nonce=nonce)
            hash = self.rpc[LIGHTNODE].send_tx(tx, wait_for_catchup=False)

            self.log.info(f"sent {value: <5} to {receiver}, tx: {hash}")
            txs.append((hash, receiver, value))

        # wait for txs to be mined
        for (hash, _, _) in txs:
            self.log.info(f"waiting for tx {hash}")
            self.rpc[FULLNODE0].wait_for_receipt(hash)

        # also create some blocks with multiple transactions
        parent_hash = self.rpc[FULLNODE0].block_by_epoch("latest_mined")['hash']
        block_txs = []

        for nonce in range(num_txs, 2 * num_txs):
            # generate random account and value
            receiver, _ = self.rpc[LIGHTNODE].rand_account()
            value = random.randint(1000, 100000)

            # create and store tx
            tx = self.rpc[LIGHTNODE].new_tx(receiver=receiver, value=value, nonce=nonce)
            block_txs.append(tx)
            hash = tx.hash_hex()

            self.log.info(f"sent {value: <5} to {receiver}, tx: {hash}")
            txs.append((hash, receiver, value))

        block_hash = self.rpc[FULLNODE0].generate_custom_block(parent_hash = parent_hash, referee = [], txs = block_txs)
        self.log.info(f"block {hash} created with {num_txs} transactions")

        # generate some more blocks to ensure our block is executed
        # and the corresponding witness is available on the light node
        self.rpc[FULLNODE0].generate_blocks(30)

        self.log.info(f"Pass 1 - all txs relayed\n")
        # ------------------------------------------------
        self.log.info(f"Retrieving txs through light node...")

        # sync blocks to make sure the light client has the header with the latest state
        self.log.info("syncing blocks...")
        sync_blocks(self.nodes)

        for (hash, _, _) in txs:
            self.check_tx(hash)      # cfx_getTransactionByHash
            self.check_receipt(hash) # cfx_getTransactionReceipt
            self.log.info(f"tx {hash} correct")

        self.log.info(f"Pass 2 - all txs retrieved\n")
        # ------------------------------------------------
        self.log.info(f"Generating incorrect blocks...")

        # save the latest epoch, guaranteed to have all the new balances
        epoch_before_blamed_blocks = self.rpc[FULLNODE0].epoch_number()

        # generate some incorrect blocks
        # NOTE: we avoid 51% attacks as it could cause some inconsistency during syncing
        incorrect_blocks = []

        for ii in range(num_blocks):
            if random.random() < 0.80:
                self.generate_correct_block(FULLNODE0)
            else:
                hash = self.generate_incorrect_block(FULLNODE0)
                incorrect_blocks.append((epoch_before_blamed_blocks + ii + 1, hash))

        self.log.info(f"Generated incorrect blocks: {incorrect_blocks}")

        # generate some correct blocks to make sure we are confident about the previous one
        for _ in range(num_blocks):
            self.generate_correct_block(FULLNODE0)

        self.log.info(f"Pass 3 - blame info correct\n")
        # ------------------------------------------------
        self.log.info(f"Checking the resulting account balances through the light node...")

        # sync blocks to make sure the light client has the header with the latest state
        self.log.info("syncing blocks...")
        sync_blocks(self.nodes)

        latest_epoch = self.rpc[FULLNODE0].epoch_number()

        # wait to make sure blame verification completes before we send queries
        time.sleep(2)

        # check balances for each address on all nodes
        for (_, receiver, value) in txs:
            # pick random epoch from the ones that have all balance information
            epoch = random.randint(epoch_before_blamed_blocks, latest_epoch - 26)

            node0_balance = self.rpc[FULLNODE0].get_balance(receiver)
            node1_balance = self.rpc[FULLNODE1].get_balance(receiver)
            node2_balance = self.rpc[LIGHTNODE].get_balance(receiver, epoch=hex(epoch))

            assert_equal(node0_balance, value)
            assert_equal(node1_balance, value)
            assert_equal(node2_balance, value)

            self.log.info(f"account {receiver} correct")

        self.log.info(f"Pass 4 - balances retrieved correctly\n")

    def check_tx(self, hash):
        node0_tx = self.rpc[FULLNODE0].get_tx(hash)
        light_tx = self.rpc[LIGHTNODE].get_tx(hash)

        # NOTE: the current light rpc implementation only retrieves the tx, does
        # not retrieve receipts or tx addresses. this will be implemented later
        node0_tx["blockHash"] = None
        node0_tx["transactionIndex"] = None
        node0_tx["status"] = None

        assert_equal(light_tx, node0_tx)

    def check_receipt(self, hash):
        node0_receipt = self.rpc[FULLNODE0].get_transaction_receipt(hash)
        light_receipt = self.rpc[LIGHTNODE].get_transaction_receipt(hash)
        assert_equal(node0_receipt, light_receipt)


if __name__ == "__main__":
    TxRelayTest().main()
