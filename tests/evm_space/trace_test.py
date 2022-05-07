#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils
import rlp

from conflux.filter import Filter
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.util import *
from test_framework.mininode import *
from base import Web3Base

EVM_CONTRACT_PATH = "../contracts/CrossSpaceEventTest/CrossSpaceEventTestEVMSide.bytecode"

def encode_u256(number):
    return ("%x" % number).zfill(64)

def encode_bytes20(hex):
    return hex.ljust(64, '0')

def number_to_topic(number):
    return "0x" + encode_u256(number)

class TraceTest(Web3Base):
    def run_test(self):
        # initialize Conflux account
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')

        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 1 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))

        # deploy EVM space contract
        evmContractAddr = self.deploy_evm_space(EVM_CONTRACT_PATH)
        print(f'EVM contract: {evmContractAddr}')

        evm_next_nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        evm_tx_hashes = []

        def emitEVM(n):
            nonlocal evm_next_nonce, evm_tx_hashes
            data_hex = (encode_hex_0x(keccak(b"emitEVM(uint256)"))[:10] + encode_u256(n))
            tx, hash = self.construct_evm_tx(receiver=evmContractAddr, data_hex=data_hex, nonce = evm_next_nonce)
            evm_next_nonce += 1
            evm_tx_hashes.append(hash)
            return tx

        # generate ledger
        block_0 = self.rpc.block_by_epoch("latest_mined")['hash']

        eth_tx = emitEVM(13)
        block_a = self.rpc.generate_custom_block(parent_hash = block_0, referee = [], txs = [
            eth_tx,
        ])

        epoch_a = self.rpc.block_by_hash(block_a)['epochNumber']

        # make sure transactions have been executed
        parent_hash = block_a

        for _ in range(5):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        for h in evm_tx_hashes:
            receipt = self.w3.eth.waitForTransactionReceipt(h)
            assert_equal(receipt["status"], 1)

        filter = { "fromBlock": epoch_a }
        traces = self.nodes[0].ethrpc.trace_filter(filter)
        assert_equal(len(traces), 1)
        assert_ne(traces[0]["result"], None)
        assert_equal(traces[0]["transactionHash"], encode_hex_0x(evm_tx_hashes[0]))
        assert_equal(traces[0]["transactionPosition"], 0)
        assert_equal(traces[0]["valid"], True)

        traces = self.nodes[0].ethrpc.trace_block(epoch_a)
        assert_equal(len(traces), 1)
        assert_ne(traces[0]["result"], None)
        assert_equal(traces[0]["transactionHash"], encode_hex_0x(evm_tx_hashes[0]))
        assert_equal(traces[0]["transactionPosition"], 0)
        assert_equal(traces[0]["valid"], True)

        traces2 = self.nodes[0].ethrpc.trace_block({ "blockHash": block_a })
        assert_equal(traces2, traces)

        block_a_txs_evm = self.nodes[0].eth_getBlockByHash(block_a, False)["transactions"]
        traces = self.nodes[0].ethrpc.trace_transaction(block_a_txs_evm[0])
        assert_equal(len(traces), 1)
        assert_ne(traces[0]["result"], None)
        assert_equal(traces[0]["transactionHash"], encode_hex_0x(evm_tx_hashes[0]))
        assert_equal(traces[0]["transactionPosition"], 0)
        assert_equal(traces[0]["valid"], True)

        self.log.info("Pass")

    def deploy_evm_space(self, bytecode_path):
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), bytecode_path)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()

        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)

        signed = self.evmAccount.signTransaction({
            "to": None,
            "value": 0,
            "gasPrice": 1,
            "gas": 500000,
            "nonce": nonce,
            "chainId": 10,
            "data": bytecode,
        })

        tx_hash = signed["hash"]
        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        assert_equal(tx_hash, return_tx_hash)

        self.rpc.generate_block(1)
        self.rpc.generate_blocks(20, 1)
        receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        assert_equal(receipt["status"], 1)
        addr = receipt["contractAddress"]
        return addr

if __name__ == "__main__":
    TraceTest().main()
