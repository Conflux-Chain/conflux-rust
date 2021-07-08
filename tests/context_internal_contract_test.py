#!/usr/bin/env python3
import os
import eth_utils

from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "contracts/ContextUser_bytecode.dat"

class ContextInternalContractTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

    def run_test(self):
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        # deploy storage test contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        tx = self.rpc.new_contract_tx(receiver="", data_hex=bytecode, sender=sender, priv_key=priv_key, storage_limit=20000)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        contractAddr = receipt["contractCreated"]
        assert_is_hex_string(contractAddr)

        #                      ---        ---        ---        ---
        #                  .- | A | <--- | C | <--- | D | <--- | E | <--- ...
        #           ---    |   ---        ---        ---        ---
        # ... <--- | P | <-*                          .
        #           ---    |   ---                    .
        #                  .- | B | <..................
        #                      ---

        #               0 --- A --- C --- B --- D ---
        # block number: x  | x+1 | x+2 | x+3 | x+4 |
        # epoch number: y  | y+1 | y+2 |   y + 3   |

        start_nonce = self.rpc.get_nonce(self.rpc.GENESIS_ADDR)

        epoch_number_p = int(self.rpc.block_by_epoch("latest_mined")['epochNumber'], 0)
        block_number_p = int(self.rpc.block_by_epoch("latest_mined")['epochNumber'], 0)
        assert_equal(epoch_number_p, block_number_p)

        block_p = self.rpc.block_by_epoch("latest_mined")['hash']

        txs = [
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"getBlockNumber()")), nonce = start_nonce + 0, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"getEpochNumber()")), nonce = start_nonce + 1, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"getBlockNumber()")), nonce = start_nonce + 2, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"getEpochNumber()")), nonce = start_nonce + 3, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"getBlockNumber()")), nonce = start_nonce + 4, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"getEpochNumber()")), nonce = start_nonce + 5, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"getBlockNumber()")), nonce = start_nonce + 6, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"getEpochNumber()")), nonce = start_nonce + 7, sender=sender, priv_key=priv_key),
        ]

        block_a = self.rpc.generate_custom_block(parent_hash = block_p, referee = [], txs = txs[0:2])
        block_c = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = txs[2:4])
        block_b = self.rpc.generate_custom_block(parent_hash = block_p, referee = [], txs = txs[4:6])
        block_d = self.rpc.generate_custom_block(parent_hash = block_c, referee = [block_b], txs = txs[6:8])

        # make sure transactions have been executed
        parent_hash = block_d

        for _ in range(5):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        # transactions in block A
        # note: topic-1 of each log is the emitted block/epoch number
        block_number_a = int(self.rpc.get_transaction_receipt(txs[0].hash_hex())['logs'][0]['topics'][1], 16)
        epoch_number_a = int(self.rpc.get_transaction_receipt(txs[1].hash_hex())['logs'][0]['topics'][1], 16)

        assert_equal(block_number_a, block_number_p + 1)
        assert_equal(epoch_number_a, epoch_number_p + 1)

        # transactions in block B
        block_number_b = int(self.rpc.get_transaction_receipt(txs[4].hash_hex())['logs'][0]['topics'][1], 16)
        epoch_number_b = int(self.rpc.get_transaction_receipt(txs[5].hash_hex())['logs'][0]['topics'][1], 16)

        assert_equal(block_number_b, block_number_p + 3)
        assert_equal(epoch_number_b, epoch_number_p + 3)

        # transactions in block C
        block_number_c = int(self.rpc.get_transaction_receipt(txs[2].hash_hex())['logs'][0]['topics'][1], 16)
        epoch_number_c = int(self.rpc.get_transaction_receipt(txs[3].hash_hex())['logs'][0]['topics'][1], 16)

        assert_equal(block_number_c, block_number_p + 2)
        assert_equal(epoch_number_c, epoch_number_p + 2)

        # transactions in block d
        block_number_d = int(self.rpc.get_transaction_receipt(txs[6].hash_hex())['logs'][0]['topics'][1], 16)
        epoch_number_d = int(self.rpc.get_transaction_receipt(txs[7].hash_hex())['logs'][0]['topics'][1], 16)

        assert_equal(block_number_d, block_number_p + 4)
        assert_equal(epoch_number_d, epoch_number_p + 3)

        self.log.info("Pass")

if __name__ == "__main__":
    ContextInternalContractTest().main()
