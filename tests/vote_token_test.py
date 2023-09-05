#!/usr/bin/env python3

from conflux.utils import priv_to_addr
from eth_utils import decode_hex
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.contracts import ConfluxTestFrameworkForContract
from test_framework.block_gen_thread import BlockGenThread
from test_framework.mininode import *
from test_framework.util import *

from web3 import Web3
from web3.contract import Contract
import os
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

    def setup_contract(self):
        self.token_contract = self.cfx_transact("DummyErc20").deploy()
        self.vote_contract = self.cfx_transact("AdvancedTokenVote1202").deploy()
        self.log.info("Initializing contract")
        self.accounts = [a[0] for a in self.new_address_and_transfer(5)]

    def run_test(self):
        start_p2p_connection(self.nodes)
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        self.token_contract = self.cfx_transact("DummyErc20").deploy()
        self.vote_contract = self.cfx_transact("AdvancedTokenVote1202").deploy()
        self.log.info("Initializing contract")
        self.accounts = self.initialize_accounts(5)

        self.vote_contract.functions.createIssue(i, self.token_contract.address, [j for j in range(self.num_of_options)], [Web3.toChecksumAddress(priv_to_addr(acc)) for acc in self.accounts], "v").cfx_transact(storage_limit = 5120)
        for _ in range(self.num_of_options):
            vote_choice = random.randint(0, self.num_of_options-1)
            self.vote_contract.functions.vote(i, vote_choice).cfx_transact(storage_limit = 5120)

    def generate_transactions(self, i):
        


if __name__ == "__main__":
    VoteTokenTest().main()
