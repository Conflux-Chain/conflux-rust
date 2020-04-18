#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import asyncio
import eth_utils

from conflux.config import default_config
from conflux.filter import Filter
from conflux.pubsub import PubSubClient
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, assert_is_hex_string, connect_nodes, sync_blocks

FULLNODE0 = 0
FULLNODE1 = 1

CONTRACT_PATH = "../contracts/EventsTestContract_bytecode.dat"
FOO_TOPIC = encode_hex_0x(keccak(b"foo()"))

NUM_CALLS = 20

class PubSubTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])

        # set up PubSub clients
        self.pubsub = [None] * self.num_nodes
        self.pubsub[FULLNODE0] = PubSubClient(self.nodes[FULLNODE0])
        self.pubsub[FULLNODE1] = PubSubClient(self.nodes[FULLNODE1])

        # connect nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    async def run_async(self):
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        # deploy two instances of the contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        _, contract1 = self.deploy_contract(sender, priv_key, bytecode)
        _, contract2 = self.deploy_contract(sender, priv_key, bytecode)

        # subscribe
        sub_all = await self.pubsub[FULLNODE1].subscribe("logs")
        sub_one = await self.pubsub[FULLNODE1].subscribe("logs", Filter(address=[contract2]).__dict__)

        # call contracts and collect receipts
        receipts = []

        for _ in range(NUM_CALLS):
            r = self.call_contract(sender, priv_key, contract1, FOO_TOPIC)
            assert(r != None)
            receipts.append(r)

            r = self.call_contract(sender, priv_key, contract2, FOO_TOPIC)
            receipts.append(r)
            assert(r != None)

        # collect pub-sub notifications
        logs1 = [l async for l in sub_all.iter()]
        logs2 = [l async for l in sub_one.iter()]

        assert_equal(len(logs1), 2 * NUM_CALLS)
        assert_equal(len(logs2), NUM_CALLS)

        # create alternative fork
        old_tip = self.nodes[FULLNODE0].best_block_hash()
        fork_hash = receipts[len(receipts) // 2]["blockHash"]
        fork_epoch = receipts[len(receipts) // 2]["epochNumber"]
        max_epoch = receipts[-1]["epochNumber"]

        new_tip = self.generate_chain(fork_hash, 2 * (max_epoch - fork_epoch))[-1]
        new_tip = self.rpc[FULLNODE0].generate_block_with_parent(new_tip, referee = [old_tip])
        new_tip = self.generate_chain(new_tip, 20)[-1]
        sync_blocks(self.nodes[:])

        # block order changed, some transactions need to be re-executed
        num_to_reexecute = sum(1 for r in receipts if r["epochNumber"] > fork_epoch)

        msg = await sub_all.next()
        assert(msg["revertTo"] != None)
        assert_equal(int(msg["revertTo"], 16), fork_epoch)

        logs = [l async for l in sub_all.iter()]
        assert_equal(len(logs), num_to_reexecute)

        self.log.info(f"Pass")

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=20000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, sender, priv_key, contract, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=20000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        return receipt

    def generate_chain(self, parent, len):
        hashes = [parent]
        for _ in range(len):
            hash = self.rpc[FULLNODE0].generate_block_with_parent(hashes[-1])
            hashes.append(hash)
        return hashes[1:]

if __name__ == "__main__":
    PubSubTest().main()
