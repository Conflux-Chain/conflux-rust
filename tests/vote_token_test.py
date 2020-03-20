#!/usr/bin/env python3

from conflux.utils import privtoaddr
from eth_utils import decode_hex
from conflux.rpc import RpcClient
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.smart_contract_bench_base import SmartContractBenchBase
from test_framework.mininode import *
from test_framework.util import *

from web3 import Web3
import os
import random


class VoteTokenTest(SmartContractBenchBase):

    def __init__(self):
        super().__init__()
        self.vote_address = ""
        self.token_address = ""
        self.token_contract = None
        self.vote_contract = None
        self.accounts = []
        self.num_of_options = 5
        self.gas_price = 1
        self.gas = 50000000
        self.tx_conf = {"gas":int_to_hex(self.gas), "gasPrice":int_to_hex(self.gas_price), "chainId":0}

    def setup_contract(self):
        file_dir = os.path.dirname(os.path.realpath(__file__))

        self.token_contract = get_contract_instance(source=os.path.join(file_dir, "contracts/vote.sol"),
                                                         contract_name="DummyErc20")
        self.vote_contract = get_contract_instance(source=os.path.join(file_dir, "contracts/vote.sol"),
                                                        contract_name="AdvancedTokenVote1202")
        self.log.info("Initializing contract")
        transaction = self.call_contract_function(self.token_contract, "constructor", [], self.default_account_key)
        self.token_address = self.wait_for_tx([transaction], True)[0]['contractCreated']
        transaction = self.call_contract_function(self.vote_contract, "constructor", [], self.default_account_key)
        self.vote_address = self.wait_for_tx([transaction], True)[0]['contractCreated']
        self.accounts = [a[0] for a in self.new_address_and_transfer(5)]

    def generate_transactions(self, i):
        self.call_contract_function(self.vote_contract, "createIssue",
                                    [i, Web3.toChecksumAddress(self.token_address), [j for j in range(self.num_of_options)],
                                     [Web3.toChecksumAddress(privtoaddr(acc)) for acc in self.accounts], "v"],
                                    self.default_account_key, self.vote_address, True, True)
        for i in range(self.num_of_options):
            self.call_contract_function(self.vote_contract, "vote", [i, random.randint(0, self.num_of_options-1)],
                                        self.default_account_key, self.vote_address, True, True)


if __name__ == "__main__":
    VoteTokenTest().main()
