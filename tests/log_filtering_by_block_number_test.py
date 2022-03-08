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
FOO_TOPIC = encode_hex_0x(keccak(b"Foo(address,uint32)"))
SNAPSHOT_EPOCH_COUNT = 50

def address_to_topic(address):
    return "0x" + address[2:].zfill(64)

def number_to_topic(number):
    return "0x" + ("%x" % number).zfill(64)

class LogFilteringTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["dev_snapshot_epoch_count"] = str(SNAPSHOT_EPOCH_COUNT)

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

        # check logs
        block_number_a = int(self.rpc.block_by_hash(block_a)['blockNumber'], 0)
        block_number_i = int(self.rpc.block_by_hash(block_i)['blockNumber'], 0)

        self.check_logs(block_number_a, block_number_i, sender)

        # check logs in old era
        for _ in range(10 * SNAPSHOT_EPOCH_COUNT):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        self.check_logs(block_number_a, block_number_i, sender)

        # get-logs-filter-max-block-number-range should limit the number of blocks queried.
        self.stop_node(0)
        self.start_node(0, ["--get-logs-filter-max-block-number-range", "16"])
        filter = Filter(from_block="0x1", to_block="0x10", topics=[FOO_TOPIC])
        # should not raise error
        self.rpc.get_logs(filter)
        filter = Filter(from_block="0x01", to_block="0x11", topics=[FOO_TOPIC])
        assert_raises_rpc_error(None, None, self.rpc.get_logs, filter)

        self.log.info("Pass")

    def check_logs(self, first_block_number, last_block_number, sender):
        # check the number of logs returned for different ranges
        for from_block in range(first_block_number, last_block_number + 1):
            for to_block in range(from_block, last_block_number + 1):
                filter = Filter(from_block=hex(from_block), to_block=hex(to_block))
                logs = self.rpc.get_logs(filter)
                assert_equal(len(logs), to_block - from_block + 1)

        # check the event parameters in each block
        for block_number in range(first_block_number, last_block_number + 1):
            logs = self.rpc.get_logs(Filter(from_block=hex(block_number), to_block=hex(block_number)))
            assert_equal(len(logs), 1)
            assert_equal(logs[0]["topics"][0], FOO_TOPIC)
            assert_equal(logs[0]["topics"][1], address_to_topic(sender))
            assert_equal(logs[0]["topics"][2], number_to_topic(block_number - first_block_number + 1))

if __name__ == "__main__":
    LogFilteringTest().main()
