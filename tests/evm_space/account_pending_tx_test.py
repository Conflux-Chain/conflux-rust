import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from base import Web3Base
from conflux.config import default_config
from test_framework.util import *

class EVMAccountPendingTxTest(Web3Base):
    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')
        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')

        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 100,
            "gasPrice": 1,
            "gas": 21000,
            "nonce": 1,
            "chainId": self.TEST_CHAIN_ID,
        })
        self.w3.eth.sendRawTransaction(signed["rawTransaction"])

        pendingTx = self.nodes[0].eth_getAccountPendingTransactions(self.evmAccount.address)
        assert_equal(pendingTx["pendingCount"], "0x1")
        assert_equal(pendingTx["firstTxStatus"]["pending"], "futureNonce")
        assert_equal(pendingTx["pendingTransactions"][0]["nonce"], "0x1")
        assert_equal(pendingTx["pendingTransactions"][0]["blockHash"], None)
        assert_equal(pendingTx["pendingTransactions"][0]["status"], None)

if __name__ == "__main__":
    EVMAccountPendingTxTest().main()