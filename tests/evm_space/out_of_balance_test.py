#!/usr/bin/env python3
import os, sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.config import default_config
from base import Web3Base
from test_framework.util import assert_equal


class OutOfBalanceTest(Web3Base):
    def run_test(self):
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": default_config["TOTAL_COIN"],
            "gasPrice": 2,
            "gas": 210000,
            "nonce": nonce,
            "chainId": 10,
        })

        try:
            self.w3.eth.sendRawTransaction(signed["rawTransaction"])
            AssertionError("expect out of balance error")
        except Exception as e:
            assert_equal(str(e), "{'code': -32003, 'message': 'insufficient funds for transfer'}")
            return

if __name__ == "__main__":
    OutOfBalanceTest().main()
