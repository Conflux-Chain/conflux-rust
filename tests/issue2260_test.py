#!/usr/bin/env python3
import os
import eth_utils

from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "contracts/EventsTestContract_bytecode.dat"
FOO_TOPIC = encode_hex_0x(keccak(b"Foo(address,uint32)"))

def number_to_topic(number):
    return "0x" + ("%x" % number).zfill(64)

class Issue2260(ConfluxTestFramework):
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

        #                              ---
        #           .-----------------| D |....
        #           V                  ---    |
        #          ---      ---      ---      ---
        # ... <-- | A | <- | B | <- | C | <- | E | <- ...
        #          ---      ---      ---      ---
        #
        #                 A --- B --- C --- D --- E
        # block number    0  |  1  |  2  |  3  |  4  |
        # epoch number    0  |  1  |  2  |     3     |

        start_nonce = self.rpc.get_nonce(self.rpc.GENESIS_ADDR)

        txs = [
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 0, sender=sender, priv_key=priv_key, storage_limit=64),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 1, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 2, sender=sender, priv_key=priv_key),
            self.rpc.new_contract_tx(receiver=contractAddr, data_hex=encode_hex_0x(keccak(b"foo()")), nonce = start_nonce + 3, sender=sender, priv_key=priv_key),
        ]

        block_0 = self.rpc.block_by_epoch("latest_mined")['hash']
        epoch_0 = int(self.rpc.block_by_hash(block_0)['epochNumber'], 0)
        block_number_0 = int(self.rpc.block_by_hash(block_0)['blockNumber'], 0)

        block_a = self.rpc.generate_custom_block(parent_hash = block_0, referee = [], txs = [])
        block_b = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = [])
        block_c = self.rpc.generate_custom_block(parent_hash = block_b, referee = [], txs = [])
        block_d = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = txs[0:2])
        block_e = self.rpc.generate_custom_block(parent_hash = block_c, referee = [block_d], txs = txs[2:4])

        # make sure transactions have been executed
        parent_hash = block_e

        for _ in range(5):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        # check logs
        block_number_a = int(self.rpc.block_by_hash(block_a)['blockNumber'], 0)
        block_number_d = int(self.rpc.block_by_hash(block_d)['blockNumber'], 0)

        filter = Filter(from_block=hex(block_number_a), to_block=hex(block_number_d))
        logs = self.rpc.get_logs(filter)
        assert_equal(len(logs), 2)
        assert_equal(logs[0]["topics"][2], number_to_topic(1))
        assert_equal(logs[1]["topics"][2], number_to_topic(2))

        self.log.info("Pass")

if __name__ == "__main__":
    Issue2260().main()
