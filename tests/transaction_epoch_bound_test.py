#!/usr/bin/env python3
from conflux.utils import encode_hex, bytes_to_int, privtoaddr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from conflux.rpc import RpcClient
from jsonrpcclient.exceptions import ReceivedErrorResponseError

class TransactionTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.conf_parameters["transaction_epoch_bound"] = "30"

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        genesis_key = default_config["GENESIS_PRI_KEY"]
        receiver_sk, _ = ec_random_keys()
        receiver_addr = privtoaddr(receiver_sk)
        client = RpcClient(self.nodes[0])

        value = 100000000;
        tx = create_transaction(pri_key = genesis_key, receiver=receiver_addr, value = value, nonce = 0, gas_price = 1, epoch_height = 0)
        client.send_tx(tx)
        block_gen_thread = BlockGenThread(self.nodes, self.log, interval_base=0.1)
        block_gen_thread.start()
        self.log.info("Wait for the first transaction to go through with epoch_height = 0...")
        wait_until(lambda: parse_as_int(self.nodes[0].cfx_getBalance(eth_utils.encode_hex(receiver_addr))) == value)
        self.log.info("Wait for generating more than 50 epochs")
        wait_until(lambda: parse_as_int(client.block_by_hash(client.best_block_hash())['height']) > 50)
        block_gen_thread.stop()
        self.log.info("Now block count:%d", self.nodes[0].getblockcount())

        tx = create_transaction(pri_key = genesis_key, receiver=receiver_addr, value = value, nonce = 1, gas_price = 1, epoch_height = 0)
        try:
            client.send_tx(tx)
            self.log.info("Bad transaction not rejected!")
            assert(False)
        except ReceivedErrorResponseError:
            self.log.info("Bad transaction rejected.")
        except:
            self.log.info("Unexpected error!")
            assert(False)
        assert(parse_as_int(self.nodes[0].cfx_getBalance(eth_utils.encode_hex(receiver_addr))) == value)

        epoch_height = parse_as_int(client.block_by_hash(client.best_block_hash())['height'])
        tx = create_transaction(pri_key = genesis_key, receiver=receiver_addr, value = value, nonce = 1, gas_price = 1, epoch_height = epoch_height)
        client.send_tx(tx)
        block_gen_thread = BlockGenThread(self.nodes, self.log, interval_base=0.1)
        block_gen_thread.start()
        self.log.info("Wait for the first transaction to go through with epoch_height = " + str(epoch_height) + "...")
        wait_until(lambda: parse_as_int(self.nodes[0].cfx_getBalance(eth_utils.encode_hex(receiver_addr))) == 2 * value)
        block_gen_thread.stop()
        self.log.info("Now block count:%d", self.nodes[0].getblockcount())
        self.log.info("Pass!")


if __name__ == "__main__":
    TransactionTest().main()
