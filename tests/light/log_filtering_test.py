#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils

from conflux.config import default_config
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, assert_is_hex_string, assert_is_hash_string
from test_framework.util import *

CONTRACT_PATH = "../contracts/EventsTestContract_bytecode.dat"
CONSTRUCTED_TOPIC = encode_hex_0x(keccak(b"Constructed(address)"))
CALLED_TOPIC = encode_hex_0x(keccak(b"Called(address,uint32)"))
NUM_CALLS = 20

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

class LogFilteringTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])
        self.start_node(LIGHTNODE, ["--light"], phase_to_wait=None)

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])
        self.rpc[LIGHTNODE] = RpcClient(self.nodes[LIGHTNODE])

        # connect archive nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    def generate_correct_block(self, node=None):
        if node is None: node = self.random_full_node()
        return self.rpc[node].generate_block()

    def run_test(self):
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        # deploy contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        _, contractAddr = self.deploy_contract(sender, priv_key, bytecode)
        self.log.info("contract deployed")

        contract_epoch = hex(self.rpc[FULLNODE0].epoch_number())

        # call method once
        receipt = self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"foo()")))
        call_epoch = hex(self.rpc[FULLNODE0].epoch_number())

        # deploy another instance of the contract
        _, contractAddr2 = self.deploy_contract(sender, priv_key, bytecode)

        # call method multiple times
        for ii in range(0, NUM_CALLS - 3):
            self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"foo()")))

        # make sure we have enough blocks to be certain about the validity of previous blocks
        self.log.info("generating blocks...")
        for _ in range(50):
            self.generate_correct_block(FULLNODE0)

        self.log.info("syncing full nodes...")
        sync_blocks(self.nodes[FULLNODE0:FULLNODE1])

        # connect light node to full nodes
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE0)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE1)

        # make sure we all nodes are in sync
        self.log.info("syncing light node...")
        sync_blocks(self.nodes[:])

        # retrieve contract code
        self.log.info("retrieving contract code...")
        self.check_code(contractAddr, contract_epoch)

        # apply filter, we expect a single log with 2 topics
        self.log.info("testing filter range...")
        self.check_filter(Filter(from_epoch="earliest", to_epoch=contract_epoch))
        self.check_filter(Filter(from_epoch="earliest", to_epoch=call_epoch))
        self.check_filter(Filter())
        self.check_filter(Filter(from_epoch="0x0", to_epoch="0x0"))

        # apply filter for specific block, we expect a single log with 3 topics
        self.check_filter(Filter(block_hashes=[receipt["blockHash"]]))

        # apply filter for specific topics
        self.log.info("testing filter topics...")
        self.check_filter(Filter(topics=[CONSTRUCTED_TOPIC]))
        self.check_filter(Filter(topics=[CALLED_TOPIC]))
        self.check_filter(Filter(topics=[None, self.address_to_topic(sender)]))
        self.check_filter(Filter(topics=[CALLED_TOPIC, None, [self.number_to_topic(3), self.number_to_topic(4)]]))

        # apply filter with limit
        self.log.info("testing filter limit...")
        self.check_filter(Filter(limit=("0x%x" % (NUM_CALLS // 2))))

        # apply filter for specific contract address
        self.log.info("testing address filtering...")
        self.check_filter(Filter(address=[contractAddr]))
        self.check_filter(Filter(address=[contractAddr2]))

        self.log.info("Pass")

    def check_filter(self, filter):
        assert_equal(self.rpc[LIGHTNODE].get_logs(filter), self.rpc[FULLNODE0].get_logs(filter))

    def check_code(self, address, epoch):
        assert_equal(self.rpc[LIGHTNODE].get_code(address, epoch), self.rpc[FULLNODE0].get_code(address, epoch))

    def address_to_topic(self, address):
        return "0x" + address[2:].zfill(64)

    def number_to_topic(self, number):
        return "0x" + ("%x" % number).zfill(64)

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=1000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], 0)
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, sender, priv_key, contract, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=1000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], 0)
        return receipt

if __name__ == "__main__":
    LogFilteringTest().main()
