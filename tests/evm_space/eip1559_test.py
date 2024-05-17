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

class Eip1559Test(Web3Base):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["evm_chain_id"] = str(10)
        self.conf_parameters["evm_transaction_block_ratio"] = str(1)
        self.conf_parameters["executive_trace"] = "true"
        self.conf_parameters["cip1559_transition_height"] = str(1)

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
        print(f'Using Conflux account {self.cfxAccount}')
        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 1 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))

        x = b32_address_to_hex("NET10:TYPE.USER:AAR8JZYBZV0FHZREAV49SYXNZUT8S0JT1ASMXX99XH")
        y = b32_address_to_hex('NET10:TYPE.BUILTIN:AAEJUAAAAAAAAAAAAAAAAAAAAAAAAAAAA27GYVFYR7')
        ret = self.nodes[0].debug_getTransactionsByEpoch("0x1")
        assert_equal(len(ret), 1)

        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        signed = self.evmAccount.signTransaction({
            "type": "0x2",
            "to": self.evmAccount.address,
            "value": 1,
            "gas": 210000,
            'maxFeePerGas': 1,
            'maxPriorityFeePerGas': 1,
            "nonce": nonce,
            "chainId": 10,
        })
        self.log.info("Signed transaction %s", signed)

        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        self.rpc.generate_block(1)
        self.rpc.generate_blocks(20, 1)
        receipt = self.w3.eth.waitForTransactionReceipt(return_tx_hash)

        assert_equal(receipt["status"], 1)
        # TODO check EIP1559 gas usage
        # assert_equal(receipt["gasUsed"], 210000 / 4 * 3)
        assert_equal(receipt["txExecErrorMsg"], None)

        tx = self.w3.eth.get_transaction(return_tx_hash)
        self.log.info("Get transaction from node %s", tx)
        assert_equal(receipt["status"], 1)

        # Check if another node can decode EIP1559 transactions
        sync_blocks(self.nodes)
        ret1 = self.nodes[0].debug_getTransactionsByEpoch(hex(receipt["blockNumber"]))
        ret2 = self.nodes[1].debug_getTransactionsByBlock(encode_hex_0x(tx["blockHash"]))
        assert_equal(len(ret1), 1)
        assert_equal(len(ret2), 1)
        assert_equal(ret1[0], ret2[0])


        fee_history = self.nodes[0].eth_feeHistory(5, "latest", [25, 75])
        assert_equal(len(fee_history['base_fee_per_gas']), 6)
        assert_equal(len(fee_history['gas_used_ratio']), 5)
        assert_equal(len(fee_history['reward']), 5)

        assert_greater_than(int(self.nodes[0].cfx_getFeeBurnt(), 0), 0)

        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        for i in range(1, 10):
            signed = self.evmAccount.signTransaction({
                "type": "0x2",
                "to": self.evmAccount.address,
                "value": 1,
                "gas": 21000,
                'maxFeePerGas': 20* (10**9),
                'maxPriorityFeePerGas': 1,
                "nonce": i,
                "chainId": 10,
            })
            return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        self.rpc.generate_block(10)
        self.rpc.generate_blocks(20, 1)
        receipt = self.w3.eth.waitForTransactionReceipt(return_tx_hash)
        assert_equal(receipt["cumulativeGasUsed"], 21000 * 9)
        assert_equal(receipt["gasUsed"], 21000)


if __name__ == "__main__":
    Eip1559Test().main()