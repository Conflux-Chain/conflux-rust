#!/usr/bin/env python3
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from test_framework.util import *
from conflux.config import default_config
from base import Web3Base

class EvmTx2ReceiptTest(Web3Base):

    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')
        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 1 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))

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
        assert_equal(receipt["gasUsed"], 210000 / 4 * 3)
        assert_equal(receipt["txExecErrorMsg"], None)

        tx = self.w3.eth.get_transaction(return_tx_hash)
        assert_equal(receipt["status"], 1)


if __name__ == "__main__":
    EvmTx2ReceiptTest().main()