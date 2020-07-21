#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils

from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, assert_is_hex_string, connect_nodes, sync_blocks

CONTRACT_PATH = "../contracts/simple_storage.dat"

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

SNAPSHOT_EPOCH_COUNT = 50

class StorageRootTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.conf_parameters["dev_snapshot_epoch_count"] = str(SNAPSHOT_EPOCH_COUNT)

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

        # connect nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE0)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE1)

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

        # call contract throughout a few eras
        self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"increment()")))
        self.rpc[FULLNODE0].generate_blocks(SNAPSHOT_EPOCH_COUNT)
        self.call_contract(sender, priv_key, contractAddr, encode_hex_0x(keccak(b"increment()")))
        self.rpc[FULLNODE0].generate_blocks(SNAPSHOT_EPOCH_COUNT)

        # check storage root of non-existent contract
        root_full = self.rpc[FULLNODE0].get_storage_root("0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6", epoch=hex(1))
        root_light = self.rpc[LIGHTNODE].get_storage_root("0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6", epoch=hex(1))
        assert_equal(root_full, root_light)

        # make sure the storage roots are verifiable on the light node
        latest_epoch = self.rpc[FULLNODE0].epoch_number()
        self.rpc[FULLNODE0].generate_blocks(SNAPSHOT_EPOCH_COUNT)
        sync_blocks(self.nodes)

        # check storage roots
        for epoch in range(latest_epoch):
            root_full = self.rpc[FULLNODE0].get_storage_root(contractAddr, epoch=hex(epoch))
            root_light = self.rpc[LIGHTNODE].get_storage_root(contractAddr, epoch=hex(epoch))
            assert_equal(root_full, root_light)
            self.log.info(f"Pass (epoch {epoch})")

        self.log.info("Pass")

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=20000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, sender, priv_key, contract, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        return receipt

if __name__ == "__main__":
    StorageRootTest().main()
