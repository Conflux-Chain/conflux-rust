#!/usr/bin/env python3

from conflux.utils import priv_to_addr
from eth_utils import decode_hex
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.contracts import ConfluxTestFrameworkForContract, Account
from test_framework.block_gen_thread import BlockGenThread
from test_framework.mininode import *
from test_framework.util import *

from web3 import Web3
from web3.contract import Contract
import random


class VoteTokenTest(ConfluxTestFrameworkForContract):
    def __init__(self):
        super().__init__()
        self.vote_address = ""
        self.token_address = ""
        self.token_contract: Contract = None
        self.vote_contract: Contract = None
        self.accounts = []
        self.num_of_options = 5
        self.gas_price = 1
        self.gas = CONTRACT_DEFAULT_GAS
        self.tx_conf = {"gas":int_to_hex(self.gas), "gasPrice":int_to_hex(self.gas_price)}

    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 1

    def setup_contract(self):
        self.token_contract = self.cfx_contract("DummyErc20").deploy()
        self.vote_contract = self.cfx_contract("AdvancedTokenVote1202").deploy()
        self.log.info("Initializing contract")

    def run_test(self):
        self.token_contract = self.cfx_contract("DummyErc20").deploy()
        self.vote_contract = self.cfx_contract("AdvancedTokenVote1202").deploy()
        self.log.info("Initializing contract")
        self.accounts: List[Account] = self.initialize_accounts(5)

        for i in range(1):
            self.vote_contract.functions.createIssue(i, self.token_contract.address, list(range(self.num_of_options)), [acc.address for acc in self.accounts], "v").cfx_transact(storage_limit = 5120)
            for _ in range(self.num_of_options):
                vote_choice = random.randint(0, self.num_of_options - 1)
                self.vote_contract.functions.vote(i, vote_choice).cfx_transact(storage_limit = 5120)
            


if __name__ == "__main__":
    VoteTokenTest().main()
