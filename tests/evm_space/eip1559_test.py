#!/usr/bin/env python3
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from test_framework.util import *
from conflux.config import default_config
from base import Web3Base
from test_framework.blocktools import encode_hex_0x
from conflux.address import b32_address_to_hex
from conflux.rpc import RpcClient
from web3 import Web3

BASE_PRICE = 20 * (10 ** 9)
class Eip1559Test(Web3Base):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["evm_chain_id"] = str(10)
        self.conf_parameters["evm_transaction_block_ratio"] = str(1)
        self.conf_parameters["executive_trace"] = "true"
        self.conf_parameters["cip1559_transition_height"] = str(1)
        self.conf_parameters["min_eth_base_price"] = 20 * (10**9)
        self.conf_parameters["tx_pool_allow_gas_over_half_block"] = "true"

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.start_node(1, ["--archive"])
        connect_nodes(self.nodes, 0 , 1)
        self.rpc = RpcClient(self.nodes[0])
        ip = self.nodes[0].ip
        port = self.nodes[0].ethrpcport
        self.w3 = Web3(Web3.HTTPProvider(f'http://{ip}:{port}/'))
        assert_equal(self.w3.isConnected(), True)


    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        self.log.info(f'Using Conflux account {self.cfxAccount}')

        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        self.log.info(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 100 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(100 * 10 ** 18))

        # x = b32_address_to_hex("NET10:TYPE.USER:AAR8JZYBZV0FHZREAV49SYXNZUT8S0JT1ASMXX99XH")
        # y = b32_address_to_hex('NET10:TYPE.BUILTIN:AAEJUAAAAAAAAAAAAAAAAAAAAAAAAAAAA27GYVFYR7')
        ret = self.nodes[0].debug_getTransactionsByEpoch("0x1")
        assert_equal(len(ret), 1)

        self.nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        tx, receipt = self.send_large_transaction()
        self.check_node_sync(tx, receipt)

        tx, receipt = self.send_large_cheap_transactions()
        self.check_node_sync(tx, receipt)
        
        tx, receipt = self.send_many_transactions_in_one_block()
        self.check_node_sync(tx, receipt, tx_num = 10)

        self.check_fee_history()

    
    def send_large_transaction(self):
        signed = self.evmAccount.signTransaction({
            "type": "0x2",
            "to": self.evmAccount.address,
            "value": 1,
            "gas": 30000000,
            'maxFeePerGas': 10 * BASE_PRICE,
            'maxPriorityFeePerGas': 1,
            "nonce": self.nonce,
            "chainId": 10,
        })
        self.nonce += 1

        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        self.rpc.generate_block(1)
        self.rpc.generate_blocks(20, 1)
        receipt = self.w3.eth.waitForTransactionReceipt(return_tx_hash)

        assert_equal(receipt["status"], 1)
        # TODO check EIP1559 gas usage
        # assert_equal(receipt["gasUsed"], 210000 / 4 * 3)
        assert_equal(receipt["txExecErrorMsg"], None)

        tx = self.w3.eth.get_transaction(return_tx_hash)

        assert_equal(Web3.toHex(tx["v"]), tx["yParity"])

        return tx, receipt
    
    def send_large_cheap_transactions(self):
        for i in range(0, 5):
            signed = self.evmAccount.signTransaction({
                "type": "0x2",
                "to": self.evmAccount.address,
                "value": 1,
                "gas": 7_500_000,
                'maxFeePerGas': BASE_PRICE,
                'maxPriorityFeePerGas': 1,
                "nonce": self.nonce + i,
                "chainId": 10,
            })
            return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        
        self.nonce += 5

        self.rpc.generate_blocks(20, 5)
        receipt = self.w3.eth.waitForTransactionReceipt(return_tx_hash)

        assert_equal(receipt["status"], 1)
        assert_equal(receipt["txExecErrorMsg"], None)

        tx = self.w3.eth.get_transaction(return_tx_hash)

        return tx, receipt
    
    def check_node_sync(self, tx, receipt, tx_num = 1):
        # Check if another node can decode EIP1559 transactions
        sync_blocks(self.nodes)
        ret1 = self.nodes[0].debug_getTransactionsByEpoch(hex(receipt["blockNumber"]))
        ret2 = self.nodes[1].debug_getTransactionsByBlock(encode_hex_0x(tx["blockHash"]))
        assert_equal(len(ret1), tx_num)
        assert_equal(len(ret2), tx_num)
        assert_equal(ret1[0], ret2[0])

    def check_fee_history(self):
        fee_history = self.nodes[0].eth_feeHistory("0x5", "latest", [21, 75])
        assert_equal(len(fee_history['baseFeePerGas']), 6)
        assert_equal(len(fee_history['gasUsedRatio']), 5)
        assert_equal(len(fee_history['reward']), 5)

        assert_greater_than(int(self.nodes[0].cfx_getFeeBurnt(), 0), 0)

    def send_many_transactions_in_one_block(self):
        for i in range(0, 10):
            signed = self.evmAccount.signTransaction({
                "type": "0x2",
                "to": self.evmAccount.address,
                "value": 1,
                "gas": 21000,
                'maxFeePerGas': BASE_PRICE,
                'maxPriorityFeePerGas': 1,
                "nonce": self.nonce + i,
                "chainId": 10,
            })
            return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        self.nonce += 10

        self.rpc.generate_block(10)
        self.rpc.generate_blocks(20, 0)
        receipt = self.w3.eth.waitForTransactionReceipt(return_tx_hash)
        assert_equal(receipt["cumulativeGasUsed"], 21000 * 10)
        assert_equal(receipt["gasUsed"], 21000)

        assert_equal(self.w3.eth.estimate_gas({"to": self.evmAccount.address}), 21000)

        tx = self.w3.eth.get_transaction(return_tx_hash)
        return tx, receipt


if __name__ == "__main__":
    Eip1559Test().main()