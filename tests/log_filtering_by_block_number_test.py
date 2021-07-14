#!/usr/bin/env python3
import os
import eth_utils

from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.transactions import COLLATERAL_UNIT_IN_DRIP
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "contracts/EventsTestContract_bytecode.dat"

class LogFilteringTest(ConfluxTestFramework):
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

        #                              ---                        ---
        #           .-----------------| D |.... .----------------| H |.....
        #           V                  ---    | V                 ---     |
        #          ---      ---      ---      ---      ---      ---      ---
        # ... <-- | A | <- | B | <- | C | <- | E | <- | F | <- | G | <- | I | <- ...
        #          ---      ---      ---      ---      ---      ---      ---
        #
        #                 A --- B --- C --- D --- E --- F --- G --- H --- I
        # block number    0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |
        # epoch number    0  |  1  |  2  |     3     |  4  |  5  |     6     |

        start_nonce = self.rpc.get_nonce(self.rpc.GENESIS_ADDR)

        txs = [
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 0, sender=sender, priv_key=priv_key, storage_limit=64),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 1, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 2, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 3, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 4, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 5, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 6, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 7, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 8, sender=sender, priv_key=priv_key),
        ]

        block_0 = self.rpc.block_by_epoch("latest_mined")['hash']
        epoch_0 = int(self.rpc.block_by_hash(block_0)['epochNumber'], 0)
        block_number_0 = int(self.rpc.block_by_hash(block_0)['blockNumber'], 0)

        block_a = self.rpc.generate_custom_block(parent_hash = block_0, referee = [], txs = [txs[0]])
        block_b = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = [txs[1]])
        block_c = self.rpc.generate_custom_block(parent_hash = block_b, referee = [], txs = [txs[2]])
        block_d = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = [txs[3]])
        block_e = self.rpc.generate_custom_block(parent_hash = block_c, referee = [block_d], txs = [txs[4]])
        block_f = self.rpc.generate_custom_block(parent_hash = block_e, referee = [], txs = [txs[5]])
        block_g = self.rpc.generate_custom_block(parent_hash = block_f, referee = [], txs = [txs[6]])
        block_h = self.rpc.generate_custom_block(parent_hash = block_e, referee = [], txs = [txs[7]])
        block_i = self.rpc.generate_custom_block(parent_hash = block_g, referee = [block_h], txs = [txs[8]])

        # make sure transactions have been executed
        parent_hash = block_i

        for _ in range(5):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        # check events
        block_number_a = int(self.rpc.block_by_hash(block_a)['blockNumber'], 0)
        block_number_i = int(self.rpc.block_by_hash(block_i)['blockNumber'], 0)

        for from_block in range(block_number_a, block_number_i + 1):
            for to_block in range(from_block, block_number_i + 1):
                filter = Filter(from_block=hex(from_block), to_block=hex(to_block), from_epoch = None, to_epoch = None)
                logs = self.rpc.get_logs(filter)
                assert_equal(len(logs), to_block - from_block + 1)

        self.log.info("Pass")

if __name__ == "__main__":
    LogFilteringTest().main()
