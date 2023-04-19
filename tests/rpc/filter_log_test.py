#!/usr/bin/env python3

import os, sys, time

sys.path.insert(1, os.path.join(sys.path[0], ".."))

import asyncio

from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    sync_blocks,
    assert_is_hex_string,
)
from conflux.address import hex_to_b32_address, b32_address_to_hex


FULLNODE0 = 0
FULLNODE1 = 1

CONTRACT_PATH = "../contracts/EventsTestContract_bytecode.dat"
FOO_TOPIC = encode_hex_0x(keccak(b"foo()"))

NUM_CALLS = 20

# default test account's private key
DEFAULT_TEST_ACCOUNT_KEY = (
    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


class FilterLogTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = "200"
        self.conf_parameters["poll_lifetime_in_seconds"] = "180"

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])

        # connect nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    async def run_async(self):
        # initialize Conflux account
        priv_key = default_config["GENESIS_PRI_KEY"]
        self.cfxAccount = self.rpc[FULLNODE0].GENESIS_ADDR

        # deploy two instances of the contract
        bytecode_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH
        )
        assert os.path.isfile(bytecode_file)
        bytecode = open(bytecode_file).read()
        contract1 = self.deploy_contract(self.rpc[FULLNODE0], bytecode)
        contract2 = self.deploy_contract(self.rpc[FULLNODE0], bytecode)

        filter = {
            "address": hex_to_b32_address(contract1),
            "fromEpoch": "0x00",
            "toEpoch": "0x1000",
        }
        filter1 = self.nodes[0].cfx_newFilter(filter)
        filter2 = self.nodes[0].cfx_newFilter(
            {"fromEpoch": "0x01", "toEpoch": "0x1000"}
        )

        logs1 = self.nodes[0].cfx_getFilterChanges(filter1)
        logs2 = self.nodes[0].cfx_getFilterChanges(filter2)
        assert_equal(len(logs1), 0)
        assert_equal(len(logs2), 0)

        # call contracts and collect receipts
        receipts = []
        for _ in range(NUM_CALLS):
            r = self.call_contract(self.rpc[FULLNODE0], contract1, FOO_TOPIC)
            assert r != None
            receipts.append(r)

            r = self.call_contract(self.rpc[FULLNODE0], contract2, FOO_TOPIC)
            receipts.append(r)
            assert r != None

        sync_blocks(self.nodes)

        # collect logs
        logs1 = self.nodes[0].cfx_getFilterChanges(filter1)
        logs2 = self.nodes[0].cfx_getFilterChanges(filter2)
        assert_equal(len(logs1), NUM_CALLS)
        assert_equal(len(logs2), 2 * NUM_CALLS)

        logs1 = self.nodes[0].cfx_getFilterChanges(filter1)
        logs2 = self.nodes[0].cfx_getFilterChanges(filter2)
        assert_equal(len(logs1), 0)
        assert_equal(len(logs2), 0)

        self.log.info(f"Pass -- filter logs with no fork")

        # create alternative fork
        old_tip = self.rpc[FULLNODE0].best_block_hash()
        old_tip_epoch = self.rpc[FULLNODE0].epoch_number()
        fork_hash = receipts[len(receipts) // 2]["blockHash"]
        fork_epoch = int(receipts[len(receipts) // 2]["epochNumber"], 16)

        self.log.info(f"Creating fork at {fork_hash[:20]}... (#{fork_epoch})")

        new_tip = self.generate_chain(fork_hash, 2 * (old_tip_epoch - fork_epoch))[-1]
        new_tip = self.rpc[FULLNODE0].generate_block_with_parent(
            new_tip, referee=[old_tip]
        )
        new_tip = self.generate_chain(new_tip, 20)[-1]
        new_tip_epoch = self.rpc[FULLNODE0].epoch_number()
        sync_blocks(self.nodes)

        self.log.info(
            f"Tip: {old_tip[:20]}... (#{old_tip_epoch}) --> {new_tip[:20]}... (#{new_tip_epoch})"
        )

        # block order changed, some transactions need to be re-executed
        num_to_reexecute = sum(
            1 for r in receipts if int(r["epochNumber"], 16) > fork_epoch
        )

        logs1 = self.nodes[0].cfx_getFilterChanges(filter1)
        logs2 = self.nodes[0].cfx_getFilterChanges(filter2)
        assert_equal(len(logs2), num_to_reexecute + 1)
        assert logs2[0]["revertTo"]

        # call cfx_getFilterLogs API
        logs1 = self.nodes[0].cfx_getFilterLogs(filter1)
        logs2 = self.nodes[0].cfx_getFilterLogs(filter2)
        assert_equal(len(logs1), NUM_CALLS + 1)
        assert_equal(len(logs2), 2 * NUM_CALLS + 2)

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())

    def deploy_contract(self, client, data_hex):
        tx = client.new_contract_tx("", data_hex, storage_limit=200000)
        assert_equal(client.send_tx(tx, True), tx.hash_hex())

        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return address

    def call_contract(self, client, contract, data_hex):
        tx = client.new_contract_tx(
            receiver=contract, data_hex=data_hex, storage_limit=200000
        )
        assert_equal(client.send_tx(tx, True), tx.hash_hex())

        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        return receipt

    def generate_chain(self, parent, len):
        hashes = [parent]
        for _ in range(len):
            hash = self.rpc[FULLNODE0].generate_block_with_parent(hashes[-1])
            hashes.append(hash)
        return hashes[1:]


if __name__ == "__main__":
    FilterLogTest().main()
