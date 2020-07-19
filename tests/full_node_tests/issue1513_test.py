#!/usr/bin/env python3
import os, sys, time
import eth_utils

sys.path.insert(1, os.path.dirname(sys.path[0]))

from conflux.config import default_config
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "../contracts/EventsTestContract_bytecode.dat"
FOO_TOPIC = encode_hex_0x(keccak(b"Foo(address,uint32)"))

ARCHIVE_NODE = 0
FULL_NODE = 1

NUM_ERAS = 10
ERA_EPOCH_COUNT = 100

class Issue1513Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

        # set era and snapshot length
        self.conf_parameters["era_epoch_count"] = str(ERA_EPOCH_COUNT)
        self.conf_parameters["dev_snapshot_epoch_count"] = str(ERA_EPOCH_COUNT // 2)

        # set other params so that nodes won't crash
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["anticone_penalty_ratio"] = "10"
        self.conf_parameters["generate_tx_period_us"] = "100000"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"

        self.conf_parameters["block_cache_gc_period_ms"] = "10"

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(ARCHIVE_NODE, ["--archive"])
        self.start_node(FULL_NODE, ["--full"], phase_to_wait=None)

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[ARCHIVE_NODE] = RpcClient(self.nodes[ARCHIVE_NODE])
        self.rpc[FULL_NODE] = RpcClient(self.nodes[FULL_NODE])

        # connect archive nodes, wait for phase changes to complete
        connect_nodes(self.nodes, ARCHIVE_NODE, FULL_NODE)

        self.nodes[ARCHIVE_NODE].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULL_NODE].wait_for_phase(["NormalSyncPhase"])

    def run_test(self):
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        # deploy contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        _, contractAddr = self.deploy_contract(sender, priv_key, bytecode)
        self.log.info(f"contract deployed at address {contractAddr}")

        # emit events throughout a few eras
        num_events = 0

        while self.rpc[ARCHIVE_NODE].epoch_number() < NUM_ERAS * ERA_EPOCH_COUNT:
            self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"foo()")))
            num_events += 1

        self.log.info(f"num_events = {num_events}")
        self.log.info(f"epoch_number = {self.rpc[ARCHIVE_NODE].epoch_number()}")

        # sync blocks and wait for gc
        sync_blocks(self.nodes)
        time.sleep(1)

        latest_checkpoint = self.rpc[FULL_NODE].epoch_number("latest_checkpoint")
        assert_greater_than(latest_checkpoint, 0)

        # filtering the whole epoch range should fail on full nodes
        filter = Filter(from_epoch="earliest", to_epoch="latest_state", topics=[FOO_TOPIC])
        logs_archive = self.rpc[ARCHIVE_NODE].get_logs(filter)
        assert_equal(len(logs_archive), num_events)

        assert_raises_rpc_error(None, None, self.rpc[FULL_NODE].get_logs, filter)

        # filtering since the latest checkpoint should yield the same result
        filter = Filter(from_epoch="latest_checkpoint", to_epoch="latest_state", topics=[FOO_TOPIC])
        logs_archive = self.rpc[ARCHIVE_NODE].get_logs(filter)
        assert_greater_than(len(logs_archive), 0)

        logs_full = self.rpc[FULL_NODE].get_logs(filter)
        assert_equal(logs_archive, logs_full)

        self.log.info("Pass")

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc[ARCHIVE_NODE].new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=1000)
        assert_equal(self.rpc[ARCHIVE_NODE].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[ARCHIVE_NODE].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, sender, priv_key, contract, data_hex):
        tx = self.rpc[ARCHIVE_NODE].new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=1000)
        assert_equal(self.rpc[ARCHIVE_NODE].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[ARCHIVE_NODE].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        return receipt

if __name__ == "__main__":
    Issue1513Test().main()
