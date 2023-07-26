from web3 import Web3
from web3.contract import ContractFunction, Contract

from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *
from conflux.address import hex_to_b32_address, b32_address_to_hex


BASE = int(1e18)
CIP118_NUMBER = 100
ZERO_ADDRESS = f"0x{'0'*40}"

def get_sponsor_contract():
    file_path = os.path.join(os.path.dirname(
        __file__), "..", "internal_contract", "metadata", "SponsorWhitelistControl.json")
    contract_dict = json.loads(open(file_path, "r").read())
    return get_contract_instance(contract_dict=contract_dict, address="0x0888000000000000000000000000000000000001")

class CIP118ActivationTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["cip118_transition_number"] = CIP118_NUMBER

    def run_test(self):
        start_p2p_connection(self.nodes)
        self.rpc = self.nodes[0].rpc
        self.client = RpcClient(self.nodes[0])

        try:
            self.read_contract(get_sponsor_contract().functions.getAvailableStoragePoints(ZERO_ADDRESS))
            raise Exception("Should fail")
        except Exception as e:
            assert_equal(e.response.data, 'VmError(InternalContract("unsupported function"))')

        self.wait_for_block(CIP118_NUMBER + 5)
        self.read_contract(get_sponsor_contract().functions.getAvailableStoragePoints(ZERO_ADDRESS))

    def wait_for_block(self, block_number, have_not_reach=False):
        if have_not_reach:
            assert_greater_than_or_equal(
                block_number,  self.client.epoch_number())
        while self.client.epoch_number() < block_number:
            self.client.generate_blocks(
                block_number - self.client.epoch_number())
            time.sleep(0.1)
            self.log.info(f"block_number: {self.client.epoch_number()}")

    def read_contract(self, contract_function: ContractFunction):
        tx = contract_function.build_transaction(
            {"gas": 3000000, "gasPrice": 1, "chainId": 1})
        return self.client.call(tx["to"], tx["data"])

if __name__ == "__main__":
    CIP118ActivationTest().main()
