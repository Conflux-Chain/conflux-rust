from web3 import Web3
from web3.contract import ContractFunction, Contract

from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.contracts import ConfluxTestFrameworkForContract, ZERO_ADDRESS
from test_framework.util import *
from test_framework.mininode import *


CIP118_NUMBER = 100

class CIP118ActivationTest(ConfluxTestFrameworkForContract):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["cip118_transition_number"] = CIP118_NUMBER
        self.conf_parameters["executive_trace"] = "true"

    def run_test(self):
        try:
            self.sponsorControl.functions.getAvailableStoragePoints(ZERO_ADDRESS).cfx_call()
            raise Exception("Should fail")
        except Exception as e:
            assert_equal(e.response.data, 'VmError(InternalContract("unsupported function"))')

        self.wait_for_block(CIP118_NUMBER + 5)
        self.sponsorControl.functions.getAvailableStoragePoints(ZERO_ADDRESS).cfx_call()

    def wait_for_block(self, block_number, have_not_reach=False):
        if have_not_reach:
            assert_greater_than_or_equal(
                block_number,  self.client.epoch_number())
        while self.client.epoch_number() < block_number:
            self.client.generate_blocks(
                block_number - self.client.epoch_number())
            time.sleep(0.1)
            self.log.info(f"block_number: {self.client.epoch_number()}")

if __name__ == "__main__":
    CIP118ActivationTest().main()
