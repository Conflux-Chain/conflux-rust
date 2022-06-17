import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from base import Web3Base
from test_framework.util import *

class EstimateAndCallTest(Web3Base):
    def run_test(self):
        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')

        call_request = {
            "to": "0x007a026f3fe3c8252f0adb915f0d924aef942f53",
            "value": "0x100",
            "chainId": self.TEST_CHAIN_ID
        }
        estimate_result = self.nodes[0].eth_estimateGas(call_request)
        assert_equal(estimate_result, "0x5208")

        call_result = self.nodes[0].eth_call(call_request)
        assert_equal(call_result, "0x")

        call_request["from"] = self.evmAccount.address
        assert_raises_rpc_error(-32015, "Can not estimate: transaction execution failed, all gas will be charged", self.nodes[0].eth_estimateGas, call_request)
        assert_raises_rpc_error(-32015, None, self.nodes[0].eth_call, call_request)

if __name__ == "__main__":
    EstimateAndCallTest().main()