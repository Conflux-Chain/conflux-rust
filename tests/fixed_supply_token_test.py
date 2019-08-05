#!/usr/bin/env python3
from conflux.utils import privtoaddr
from test_framework.smart_contract_bench_base import SmartContractBenchBase
from easysolc import Solc

from web3 import Web3
import os


class FixedTokenSupplyTokenTest(SmartContractBenchBase):

    def __init__(self):
        super().__init__()
        self.contract_address = ""
        self.contract = None
        self.accounts = []

    def setup_contract(self):
        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))
        self.contract = solc.get_contract_instance(source=os.path.join(file_dir, "contracts/fixed_supply_token.sol"),
                                                   contract_name="FixedSupplyToken")
        self.log.info("Initializing contract")

        transaction = self.call_contract_function(self.contract, "constructor", [], self.default_account_key)
        self.contract_address = self.wait_for_tx([transaction], True)[0]['contractCreated']
        self.accounts = [a[0] for a in self.new_address_and_transfer(2)]

    def generate_transactions(self, _):
        self.call_contract_function(self.contract, "transfer",
                                    [Web3.toChecksumAddress(privtoaddr(self.accounts[0])), 1000],
                                    self.default_account_key, self.contract_address, True, True)
        self.call_contract_function(self.contract, "approve",
                                    [Web3.toChecksumAddress(privtoaddr(self.accounts[1])), 500],
                                    self.accounts[0], self.contract_address, True, True)
        self.call_contract_function(self.contract, "transferFrom",
                                    [Web3.toChecksumAddress(privtoaddr(self.accounts[0])),
                                     Web3.toChecksumAddress(privtoaddr(self.default_account_key)), 300],
                                    self.accounts[1], self.contract_address, True, True)


if __name__ == "__main__":
    FixedTokenSupplyTokenTest().main()
