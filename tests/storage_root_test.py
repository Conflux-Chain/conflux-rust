#!/usr/bin/env python3
import os
import eth_utils

from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "contracts/simple_storage.dat"

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

NULL_NODE = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
SNAPSHOT_EPOCH_COUNT = 50

# TODO(thegaram): add light node tests
class StorageRootTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["dev_snapshot_epoch_count"] = str(SNAPSHOT_EPOCH_COUNT)

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])

        # connect archive nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    def run_test(self):
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        # check storage root of non-existent contract
        root = self.rpc[FULLNODE0].get_storage_root("0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6")
        assert_equal(root, None)

        # deploy storage test contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        _, contractAddr = self.deploy_contract(sender, priv_key, bytecode)

        # get storage root; expect: (D0, I0, S0) = (?, NULL, NULL)
        root0 = self.rpc[FULLNODE0].get_storage_root(contractAddr)

        assert(root0 != None)
        assert(root0["delta"]        != NULL_NODE)
        assert(root0["intermediate"] == NULL_NODE)
        assert(root0["snapshot"]     == NULL_NODE)

        # update storage; expect: (D1, I1, S1) == (?, I0, S0)
        # NOTE: call_contract will generate some blocks but it should be < SNAPSHOT_EPOCH_COUNT
        self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"increment()")))
        root1 = self.rpc[FULLNODE0].get_storage_root(contractAddr)

        assert(root1["delta"]        != root0["delta"])
        assert(root1["intermediate"] == root0["intermediate"])
        assert(root1["snapshot"]     == root0["snapshot"])

        # go to next era
        self.rpc[FULLNODE0].generate_blocks(SNAPSHOT_EPOCH_COUNT)

        # get storage root; expect: (D2, I2, S2) == (NULL, D1, ?)
        # (the previous delta trie became the current intermediate trie)
        # (note that storage root in the snapshot will not match due to differences in padding)
        root2 = self.rpc[FULLNODE0].get_storage_root(contractAddr)

        assert(root2["delta"]        == NULL_NODE)
        assert(root2["intermediate"] == root1["delta"])

        # update storage; expect: (D3, I3, S3) == (?, D2, S2)
        # NOTE: call_contract will generate some blocks but it should be < SNAPSHOT_EPOCH_COUNT
        self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"increment()")))
        root3 = self.rpc[FULLNODE0].get_storage_root(contractAddr)

        assert(root3["delta"]        != root2["delta"])
        assert(root3["intermediate"] == root2["intermediate"])
        assert(root3["snapshot"]     == root2["snapshot"])

        # go to next era
        self.rpc[FULLNODE0].generate_blocks(SNAPSHOT_EPOCH_COUNT)

        # get storage root; expect: (D4, I4, S4) == (NULL, D3, ?)
        # (the previous delta trie became the current intermediate trie)
        # (note that storage root in the snapshot will not match due to differences in padding)
        root4 = self.rpc[FULLNODE0].get_storage_root(contractAddr)

        assert(root4["delta"]        == NULL_NODE)
        assert(root4["intermediate"] == root3["delta"])

        # check if other node's storage root matches
        sync_blocks(self.nodes[:])
        root = self.rpc[FULLNODE1].get_storage_root(contractAddr)
        assert(root == root4)

        self.log.info("Pass")

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, sender, priv_key, contract, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        return receipt

if __name__ == "__main__":
    StorageRootTest().main()
