#!/usr/bin/env python3
import os
import eth_utils

from conflux.config import default_config
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "contracts/EventsTestContract_bytecode.dat"
CONSTRUCTED_TOPIC = encode_hex_0x(keccak(b"Constructed(address,address)"))
CALLED_TOPIC = encode_hex_0x(keccak(b"Called(address,uint32)"))
NUM_CALLS = 20

class LogFilteringTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        self.rpc = RpcClient(self.nodes[0])

        # apply filter, we expect no logs
        filter = Filter(from_epoch="earliest", to_epoch="latest_mined")
        result = self.rpc.get_logs(filter)
        assert_equal(result, [])

        # deploy contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        _, contractAddr = self.deploy_contract(sender, priv_key, bytecode)

        # apply filter, we expect a single log with 2 topics
        filter = Filter(from_epoch="earliest", to_epoch="latest_mined")
        logs0 = self.rpc.get_logs(filter)

        self.assert_response_format_correct(logs0)
        assert_equal(len(logs0), 1)

        assert_equal(len(logs0[0]["topics"]), 2)
        assert_equal(logs0[0]["topics"][0], CONSTRUCTED_TOPIC)
        assert_equal(logs0[0]["topics"][1], self.address_to_topic(sender))
        assert_equal(logs0[0]["data"], self.address_to_topic(sender))

        # call method
        receipt = self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"foo()")))

        # apply filter, we expect two logs with 2 and 3 topics respectively
        filter = Filter(from_epoch="earliest", to_epoch="latest_mined")
        logs1 = self.rpc.get_logs(filter)

        self.assert_response_format_correct(logs1)
        assert_equal(len(logs1), 2)
        assert_equal(logs1[0], logs0[0])

        assert_equal(len(logs1[1]["topics"]), 3)
        assert_equal(logs1[1]["topics"][0], CALLED_TOPIC)
        assert_equal(logs1[1]["topics"][1], self.address_to_topic(sender))
        assert_equal(logs1[1]["topics"][2], self.number_to_topic(1))

        # apply filter for specific block, we expect a single log with 3 topics
        filter = Filter(block_hashes=[receipt["blockHash"]])
        logs = self.rpc.get_logs(filter)

        self.assert_response_format_correct(logs)
        assert_equal(len(logs), 1)
        assert_equal(logs[0], logs1[1])

        # call many times
        for ii in range(0, NUM_CALLS - 2):
            self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"foo()")))

        # apply filter, we expect NUM_CALLS log entries with inreasing uint32 fields
        filter = Filter(from_epoch="earliest", to_epoch="latest_mined")
        logs = self.rpc.get_logs(filter)

        self.assert_response_format_correct(logs)
        assert_equal(len(logs), NUM_CALLS)

        for ii in range(2, NUM_CALLS):
            assert_equal(len(logs[ii]["topics"]), 3)
            assert_equal(logs[ii]["topics"][0], CALLED_TOPIC)
            assert(logs[ii]["topics"][1] == self.address_to_topic(sender))
            assert_equal(logs[ii]["topics"][2], self.number_to_topic(ii))

        # apply filter for specific topics
        filter = Filter(topics=[CONSTRUCTED_TOPIC])
        logs = self.rpc.get_logs(filter)
        self.assert_response_format_correct(logs)
        assert_equal(len(logs), 1)

        filter = Filter(topics=[CALLED_TOPIC])
        logs = self.rpc.get_logs(filter)
        self.assert_response_format_correct(logs)
        assert_equal(len(logs), NUM_CALLS - 1)

        filter = Filter(topics=[None, self.address_to_topic(sender)])
        logs = self.rpc.get_logs(filter)
        self.assert_response_format_correct(logs)
        assert_equal(len(logs), NUM_CALLS)

        # find logs with `CALLED_TOPIC` as 1st topic and `3` or `4` as 3rd topic
        filter = Filter(topics=[CALLED_TOPIC, None, [self.number_to_topic(3), self.number_to_topic(4)]])
        logs = self.rpc.get_logs(filter)
        self.assert_response_format_correct(logs)
        assert_equal(len(logs), 2)

        # apply filter with limit
        filter = Filter(limit=("0x%x" % (NUM_CALLS // 2)))
        logs = self.rpc.get_logs(filter)

        self.assert_response_format_correct(logs)
        assert_equal(len(logs), NUM_CALLS // 2)

        # apply filter for specific contract address
        _, contractAddr2 = self.deploy_contract(sender, priv_key, bytecode)

        filter = Filter(address=[contractAddr])
        logs = self.rpc.get_logs(filter)
        self.assert_response_format_correct(logs)
        assert_equal(len(logs), NUM_CALLS)

        filter = Filter(address=[contractAddr2])
        logs = self.rpc.get_logs(filter)
        self.assert_response_format_correct(logs)
        assert_equal(len(logs), 1)

        # apply filter to very first epoch, we expect no logs
        filter = Filter(from_epoch="0x0", to_epoch="0x0")
        result = self.rpc.get_logs(filter)
        assert_equal(result, [])

        self.log.info("Pass")

    def address_to_topic(self, address):
        return "0x" + address[2:].zfill(64)

    def number_to_topic(self, number):
        return "0x" + ("%x" % number).zfill(64)

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc.new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, sender, priv_key, contract, data_hex):
        tx = self.rpc.new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        return receipt

    def assert_response_format_correct(self, response):
        assert_equal(type(response), list)
        for log in response:
            self.assert_log_format_correct(log)

    def assert_log_format_correct(self, log):
        assert_is_hex_string(log["address"])
        assert_is_hex_string(log["epochNumber"])
        assert_is_hex_string(log["logIndex"])
        assert_is_hex_string(log["transactionIndex"])
        assert_is_hex_string(log["transactionLogIndex"])

        assert_is_hash_string(log["blockHash"])
        assert_is_hash_string(log["transactionHash"])

        assert_equal(type(log["topics"]), list)

if __name__ == "__main__":
    LogFilteringTest().main()
