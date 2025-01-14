#!/usr/bin/env python3
import time

from conflux.utils import priv_to_addr
from test_framework.smart_contract_bench_base import SmartContractBenchBase
from web3 import Web3
import os

from test_framework.util import load_contract_metadata


class FixedTokenSupplyTokenTest(SmartContractBenchBase):

    def __init__(self):
        super().__init__()
        self.contract_address = ""
        self.contract = None
        self.accounts = []

    def setup_contract(self):
        metadata = load_contract_metadata("ERC20")
        self.contract = Web3().eth.contract(
            abi=metadata["abi"],
            bytecode=metadata["bytecode"],
        )
        self.log.info("Initializing contract")

        transaction = self.call_contract_function(self.contract, "constructor", [], self.default_account_key, storage_limit=20000)
        self.contract_address = self.wait_for_tx([transaction], True)[0]['contractCreated']
        self.accounts = [a[0] for a in self.new_address_and_transfer(2)]

    def generate_transactions(self, _):
        self.call_contract_function(self.contract, "transfer",
                                    [Web3.to_checksum_address(priv_to_addr(self.accounts[0])), 1000],
                                    self.default_account_key, self.contract_address, True, True, storage_limit=512)
        self.call_contract_function(self.contract, "approve",
                                    [Web3.to_checksum_address(priv_to_addr(self.accounts[1])), 500],
                                    self.accounts[0], self.contract_address, True, True, storage_limit=512)
        self.call_contract_function(self.contract, "transferFrom",
                                    [Web3.to_checksum_address(priv_to_addr(self.accounts[0])),
                                     Web3.to_checksum_address(priv_to_addr(self.default_account_key)), 300],
                                    self.accounts[1], self.contract_address, True, True, storage_limit=512)


if __name__ == "__main__":
    FixedTokenSupplyTokenTest().main()
