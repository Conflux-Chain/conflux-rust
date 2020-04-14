#!/usr/bin/env python3
import os
import eth_utils

from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import priv_to_addr
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "contracts/simple_storage.dat"

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

class StorageRpcTest(ConfluxTestFramework):
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

    def run_test(self):
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        # deploy storage test contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        _, contractAddr = self.deploy_contract(sender, priv_key, bytecode)

        # make sure we have enough blocks to be certain about the validity of previous blocks
        for _ in range(50): self.rpc[FULLNODE0].generate_block()

        # connect light node to full nodes
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE0)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE1)

        # make sure we all nodes are in sync
        self.log.info("syncing nodes...\n")
        sync_blocks(self.nodes[:])

        # test `pos0`
        self.log.info("Retrieving single variable value `pos0` from full node...")
        res = self.rpc[FULLNODE1].get_storage_at(contractAddr, "0x0000000000000000000000000000000000000000000000000000000000000000")
        assert_equal(res, "0x00000000000000000000000000000000000000000000000000000000000004d2")

        self.log.info("Retrieving single variable value `pos0` from light node...")
        res = self.rpc[LIGHTNODE].get_storage_at(contractAddr, "0x0000000000000000000000000000000000000000000000000000000000000000")
        assert_equal(res, "0x00000000000000000000000000000000000000000000000000000000000004d2")

        self.log.info("Pass\n")

        # test `pos1[0x391694e7E0B0cCE554cb130d723A9d27458F9298]`
        self.log.info("Retrieving mapping value `pos1[...]` from full node...")
        res = self.rpc[FULLNODE1].get_storage_at(contractAddr, "0x6661e9d6d8b923d5bbaab1b96e1dd51ff6ea2a93520fdc9eb75d059238b8c5e9")
        assert_equal(res, "0x000000000000000000000000000000000000000000000000000000000000162e")

        self.log.info("Retrieving mapping value `pos1[...]` from light node...")
        res = self.rpc[LIGHTNODE].get_storage_at(contractAddr, "0x6661e9d6d8b923d5bbaab1b96e1dd51ff6ea2a93520fdc9eb75d059238b8c5e9")
        assert_equal(res, "0x000000000000000000000000000000000000000000000000000000000000162e")

        self.log.info("Pass\n")

        # test nonexistent value
        self.log.info("Retrieving nonexistent value from full node...")
        res = self.rpc[FULLNODE1].get_storage_at(contractAddr, "0x0000000000000000000000000000000000000000000000000000000000000002")
        assert_equal(res, None)

        self.log.info("Retrieving nonexistent value from light node...")
        res = self.rpc[LIGHTNODE].get_storage_at(contractAddr, "0x0000000000000000000000000000000000000000000000000000000000000002")
        assert_equal(res, None)

        self.log.info("Pass\n")

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=20000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

if __name__ == "__main__":
    StorageRpcTest().main()
