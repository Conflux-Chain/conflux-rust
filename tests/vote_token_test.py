#!/usr/bin/env python3

from conflux.transactions import CONTRACT_DEFAULT_GAS
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

from conflux_web3.contract import ConfluxContract
import random


class VoteTokenTest(ConfluxTestFramework):
    def __init__(self):
        super().__init__()
        self.vote_address = ""
        self.token_address = ""
        self.token_contract: ConfluxContract = None
        self.vote_contract: ConfluxContract = None
        self.accounts = []
        self.num_of_options = 5
        self.gas_price = 1
        self.gas = CONTRACT_DEFAULT_GAS
        self.tx_conf = {"gas":int_to_hex(self.gas), "gasPrice":int_to_hex(self.gas_price)}

    def set_test_params(self):
        self.num_nodes = 1
        self._add_genesis_secrets(5, "core")

    def setup_contract(self):
        self.token_contract = self.deploy_contract("DummyErc20")
        self.vote_contract = self.deploy_contract("AdvancedTokenVote1202")
        self.log.info("Initializing contract")

    def run_test(self):
        self.setup_contract()
        accounts = self.core_accounts[1:6]

        for i in range(1):
            self.vote_contract.functions.createIssue(i, self.token_contract.address, list(range(self.num_of_options)), [acc.address for acc in accounts], "v").transact({
                "storageLimit": 5120,
            }).executed()
            for _ in range(self.num_of_options):
                vote_choice = random.randint(0, self.num_of_options - 1)
                self.vote_contract.functions.vote(i, vote_choice).transact({
                    "storageLimit": 5120,
                }).executed()
            


if __name__ == "__main__":
    VoteTokenTest().main()
