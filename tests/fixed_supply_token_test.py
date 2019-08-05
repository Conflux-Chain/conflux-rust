from conflux.utils import privtoaddr
from test_framework.smart_contract_bench_base import SmartContractBenchBase
from easysolc import Solc

from web3 import Web3
import os


class FixedTokenSupplyTokenTest(SmartContractBenchBase):

    def __init__(self):
        super().__init__()
        self.contract_address = ""

    def setup_contract(self):
        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))
        self.contract = solc.get_contract_instance(source=os.path.join(file_dir, "contracts/fixed_supply_token.sol"),
                                                   contract_name="FixedSupplyToken")
        self.log.info("Initializing contract")

        transaction = self.call_contract_function("constructor", [], self.default_account_key)
        self.contract_address = self.wait_for_tx([transaction], True)[0]['contractCreated']

    def generate_transactions(self):
        acc1_key, _ = self.new_address_and_transfer()
        acc2_key, _ = self.new_address_and_transfer()
        for i in range(self.options.iter):
            self.call_contract_function("transfer", [Web3.toChecksumAddress(privtoaddr(acc1_key)), 1000],
                                        self.default_account_key, self.contract_address, True, True)
            self.call_contract_function("approve", [Web3.toChecksumAddress(privtoaddr(acc2_key)), 500],
                                        acc1_key, self.contract_address, True, True)
            self.call_contract_function("transferFrom", [Web3.toChecksumAddress(privtoaddr(acc1_key)),
                                                         Web3.toChecksumAddress(privtoaddr(self.default_account_key)),
                                                         300],
                                        acc2_key, self.contract_address, True, True)


if __name__ == "__main__":
    FixedTokenSupplyTokenTest().main()
