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

        epoch_number_p = int(self.rpc.block_by_epoch("latest_mined")['epochNumber'], 0)
        block_number_p = int(self.rpc.block_by_epoch("latest_mined")['epochNumber'], 0)
        assert_equal(epoch_number_p, block_number_p)

        block_p = self.rpc.block_by_epoch("latest_mined")['hash']
        block_a = self.rpc.generate_custom_block(parent_hash = block_p, referee = [], txs = [])
        block_b = self.rpc.generate_custom_block(parent_hash = block_p, referee = [], txs = [])
        block_c = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = [])
        block_d = self.rpc.generate_custom_block(parent_hash = block_c, referee = [block_b], txs = [])

        # as if executed in P
        block_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getBlockNumber()")), epoch="latest_state")
        assert_equal(int(block_number, 0), block_number_p)
        epoch_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getEpochNumber()")), epoch="latest_state")
        assert_equal(int(epoch_number, 0), epoch_number_p)

        block_e = self.rpc.generate_custom_block(parent_hash = block_d, referee = [], txs = [])

        # as if executed in A (P + 1)
        block_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getBlockNumber()")), epoch="latest_state")
        assert_equal(int(block_number, 0), block_number_p + 1)
        epoch_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getEpochNumber()")), epoch="latest_state")
        assert_equal(int(epoch_number, 0), epoch_number_p + 1)

        block_f = self.rpc.generate_custom_block(parent_hash = block_e, referee = [], txs = [])

        # as if executed in C (A + 1)
        block_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getBlockNumber()")), epoch="latest_state")
        assert_equal(int(block_number, 0), block_number_p + 2)
        epoch_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getEpochNumber()")), epoch="latest_state")
        assert_equal(int(epoch_number, 0), epoch_number_p + 2)

        block_g = self.rpc.generate_custom_block(parent_hash = block_f, referee = [], txs = [])

        # as if executed in B (C + 1)
        block_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getBlockNumber()")), epoch="latest_state")
        assert_equal(int(block_number, 0), block_number_p + 3)
        epoch_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getEpochNumber()")), epoch="latest_state")
        assert_equal(int(epoch_number, 0), epoch_number_p + 3)

        block_h = self.rpc.generate_custom_block(parent_hash = block_g, referee = [], txs = [])

        # as if executed in E (D + 2)
        block_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getBlockNumber()")), epoch="latest_state")
        assert_equal(int(block_number, 0), block_number_p + 5) # !!!
        epoch_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getEpochNumber()")), epoch="latest_state")
        assert_equal(int(epoch_number, 0), epoch_number_p + 4) # !!!

        # as if executed in E (D + 2)
        epoch_d = int(self.rpc.block_by_hash(block_d)['epochNumber'], 0)

        block_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getBlockNumber()")), epoch=hex(epoch_d))
        assert_equal(int(block_number, 0), block_number_p + 5) # !!!
        epoch_number = self.rpc.call(contractAddr, encode_hex_0x(keccak(b"getEpochNumber()")), epoch=hex(epoch_d))
        assert_equal(int(epoch_number, 0), epoch_number_p + 4) # !!!

        self.log.info("Pass")

if __name__ == "__main__":
    ContextInternalContractTest().main()
