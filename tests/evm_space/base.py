#!/usr/bin/env python3
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from test_framework.test_framework import ConfluxTestFramework
from conflux.rpc import RpcClient
from web3 import Web3
from test_framework.util import *
from eth_utils import decode_hex
from conflux.config import default_config

class Web3Base(ConfluxTestFramework):
    # default test account's private key
    DEFAULT_TEST_ACCOUNT_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    TEST_CHAIN_ID = 10

    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["evm_chain_id"] = str(10)
        self.conf_parameters["evm_transaction_block_ratio"] = str(1)
        self.conf_parameters["executive_trace"] = "true"

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

        ip = self.nodes[0].ip
        port = self.nodes[0].ethrpcport
        self.w3 = Web3(Web3.HTTPProvider(f'http://{ip}:{port}/'))
        assert_equal(self.w3.isConnected(), True)

    def cross_space_transfer(self, to, value):
        to = to.replace('0x', '')

        tx = self.rpc.new_tx(
            value=value,
            receiver="0x0888000000000000000000000000000000000006",
            data=decode_hex(f"0xda8d5daf{to}000000000000000000000000"),
            nonce=self.rpc.get_nonce(self.cfxAccount),
            gas=1000000,
        )

        self.rpc.send_tx(tx, True)

    def construct_evm_tx(self, receiver, data_hex, nonce):
        signed = self.evmAccount.signTransaction({
            "to": receiver,
            "value": 0,
            "gasPrice": 1,
            "gas": 150000,
            "nonce": nonce,
            "chainId": 10,
            "data": data_hex,
        })

        tx = [nonce, 1, 150000, bytes.fromhex(receiver.replace('0x', '')), 0, bytes.fromhex(data_hex.replace('0x', '')), signed["v"], signed["r"], signed["s"]]
        return tx, signed["hash"]

    def deploy_conflux_space(self, bytecode_path):
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), bytecode_path)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        tx = self.rpc.new_contract_tx(receiver="", data_hex=bytecode, sender=self.cfxAccount, priv_key=self.cfxPrivkey, storage_limit=20000)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        addr = receipt["contractCreated"]
        assert_is_hex_string(addr)
        return addr

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
            "chainId": int(self.conf_parameters["evm_chain_id"], 10),
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

    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')
        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 1 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))


if __name__ == "__main__":
    Web3Base().main()