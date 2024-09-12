import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from base import Web3Base
from web3 import Web3
from test_framework.util import *
from conflux.config import default_config

class EstimateAndCallTest(Web3Base):
    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')
        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')

        self.test_basic()

        self.cross_space_transfer(self.evmAccount.address, 100 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(100 * 10 ** 18))
        self.test_revert()

    def test_basic(self):
        call_request = {
            "to": "0x007a026f3fe3c8252f0adb915f0d924aef942f53",
            "value": "0x100",
            "chainId": Web3.toHex(self.TEST_CHAIN_ID)
        }
        estimate_result = self.nodes[0].eth_estimateGas(call_request)
        assert_equal(estimate_result, "0x5208")

        call_result = self.nodes[0].eth_call(call_request)
        assert_equal(call_result, "0x")

        call_request["from"] = self.evmAccount.address
        assert_raises_rpc_error(-32000, "SenderDoesNotExist", self.nodes[0].eth_estimateGas, call_request)
        assert_raises_rpc_error(-32000, None, self.nodes[0].eth_call, call_request)
    
    def test_revert(self):
        err_abi = self.load_abi_from_tests_contracts_folder("Error")
        bytecode = err_abi["bytecode"]
        abi = err_abi["abi"]
        addr = self.deploy_evm_space_by_code(bytecode)
        err_contract = self.w3.eth.contract(address=addr, abi=abi)

        data = err_contract.encodeABI(fn_name="testRequire", args=[1])
        call_request = {
            "to": addr,
            "data": data,
        }
        err_msg = "execution reverted: revert: Input must be greater than 10"
        err_data = "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001d496e707574206d7573742062652067726561746572207468616e203130000000"
        assert_raises_rpc_error(3, err_msg, self.nodes[0].eth_estimateGas, call_request, err_data_=err_data)
        assert_raises_rpc_error(3, err_msg, self.nodes[0].eth_call, call_request, err_data_=err_data)

        data = err_contract.encodeABI(fn_name="testRevert", args=[1])
        call_request = {
            "to": addr,
            "data": data,
        }
        assert_raises_rpc_error(3, err_msg, self.nodes[0].eth_estimateGas, call_request, err_data_=err_data)
        assert_raises_rpc_error(3, err_msg, self.nodes[0].eth_call, call_request, err_data_=err_data)

        data = err_contract.encodeABI(fn_name="testCustomError", args=[1])
        call_request = {
            "to": addr,
            "data": data,
        }

        custom_err_msg = "execution reverted: revert:"
        custom_err_data = "0xcf47918100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
        assert_raises_rpc_error(3, custom_err_msg, self.nodes[0].eth_estimateGas, call_request, err_data_=custom_err_data)
        assert_raises_rpc_error(3, custom_err_msg, self.nodes[0].eth_call, call_request, err_data_=custom_err_data)
        

if __name__ == "__main__":
    EstimateAndCallTest().main()