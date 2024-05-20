#!/usr/bin/env python3
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from test_framework.util import *
from conflux.config import default_config
from base import Web3Base
from test_framework.blocktools import encode_hex_0x
from conflux.address import b32_address_to_hex


class EvmTx2ReceiptTest(Web3Base):

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
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 1,
            "gas": 210000,
            "nonce": nonce,
            "chainId": 10,
        })

        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        self.rpc.generate_block(1)
        self.rpc.generate_blocks(20, 1)
        receipt = self.w3.eth.waitForTransactionReceipt(return_tx_hash)
        assert_equal(receipt["status"], 1)
        assert_equal(receipt["gasUsed"], 21000)
        assert_equal(receipt["txExecErrorMsg"], None)

        tx = self.w3.eth.get_transaction(return_tx_hash)
        assert_equal(receipt["status"], 1)

        # eth_call with unknown extra fields should work (#2471)
        self.nodes[0].eth_call({ "accessList": [] })

        # eth_call with zero sender should work (#2472)
        self.nodes[0].eth_call({ "from": "0x0000000000000000000000000000000000000000" })

        ret1 = self.nodes[0].debug_getTransactionsByEpoch(hex(receipt["blockNumber"]))
        ret2 = self.nodes[0].debug_getTransactionsByBlock(encode_hex_0x(tx["blockHash"]))
        assert_equal(len(ret1), 1)
        assert_equal(len(ret2), 1)
        assert_equal(ret1[0], ret2[0])


if __name__ == "__main__":
    EvmTx2ReceiptTest().main()