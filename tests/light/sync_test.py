#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys, random, time
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.config import default_config
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from eth_utils import encode_hex
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, connect_nodes, sync_blocks

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

ERA_EPOCH_COUNT = 100
NORMAL_CHAIN_LENGTH = 1000
BLAMED_SECTION_LENGTH = 100
BLAME_CHECK_OFFSET = 30

CONTRACT_PATH = "../contracts/EventsTestContract_bytecode.dat"
FOO_TOPIC = encode_hex_0x(keccak(b"Foo(address,uint32)"))

class LightSyncTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

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

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])
        self.start_node(LIGHTNODE, ["--light"], phase_to_wait=None)

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])
        self.rpc[LIGHTNODE] = RpcClient(self.nodes[LIGHTNODE])

        # connect nodes, wait for phase changes to complete
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE0)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE1)

        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    def run_test(self):
        # generate blocks and sync
        self.log.info(f"Generating blocks...")
        self.generate_blocks()

        self.check_headers_synced()
        self.check_witnesses_synced()

        self.log.info(f"Pass 1 -- keep up")

        # crash light node (with db reset)
        self.log.info(f"Restarting light node with db reset...")
        self.stop_node(LIGHTNODE, clean=True)
        self.start_node(LIGHTNODE, phase_to_wait=None)

        self.check_headers_synced()
        self.check_witnesses_synced()

        self.log.info(f"Pass 2 -- catch up")

        # crash light node (no db reset)
        self.log.info(f"Restarting light node without db reset...")
        self.stop_node(LIGHTNODE, clean=False)
        self.start_node(LIGHTNODE, phase_to_wait=None)

        # make sure witness sync completes
        time.sleep(5)

        self.check_headers_synced()
        self.check_witnesses_synced()

        self.log.info(f"Pass 3 -- recover from db")

    def check_headers_synced(self):
        sync_blocks(self.nodes)

    def check_witnesses_synced(self):
        latest_epoch = self.rpc[FULLNODE0].epoch_number()

        # scan all blocks for receipts
        # we need to have all correct roots to do this
        filter = Filter(from_epoch="earliest", to_epoch=hex(latest_epoch - BLAME_CHECK_OFFSET), topics=[FOO_TOPIC])

        logs_full = self.rpc[FULLNODE0].get_logs(filter)
        logs_light = self.rpc[LIGHTNODE].get_logs(filter)
        assert_equal(logs_full, logs_light)

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=1000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        address = receipt["contractCreated"]
        return receipt, address

    def generate_blocks(self):
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = encode_hex(priv_to_addr(priv_key))

        # deploy contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        _, contract_addr = self.deploy_contract(sender, priv_key, bytecode)
        self.log.info("Contract deployed")

        parent_hash = self.rpc[FULLNODE0].block_by_epoch("latest_mined")['hash']
        nonce = self.rpc[FULLNODE0].get_nonce(sender)

        hashes = []
        num_events = 0
        num_blamed = 0

        for _ in range(0, NORMAL_CHAIN_LENGTH):
            rnd = random.random()

            # ~20% of all block have events
            if rnd < 0.2:
                tx = self.rpc[FULLNODE0].new_contract_tx(
                    receiver=contract_addr,
                    data_hex=encode_hex_0x(keccak(b"foo()")),
                    sender=sender, priv_key=priv_key,
                    storage_limit=64,
                    nonce = nonce
                )

                parent_hash = self.rpc[FULLNODE0].generate_custom_block(parent_hash=parent_hash, txs=[tx], referee=[])

                nonce += 1
                hashes.append(tx.hash_hex())
                num_events += 1

            # ~10% of all blocks are incorrect and blamed
            elif rnd < 0.3:
                blame_info = {}
                blame_info['blame'] = "0x1"
                blame_info['deferredStateRoot'] = "0x1111111111111111111111111111111111111111111111111111111111111111"
                parent_hash = self.nodes[FULLNODE0].test_generateblockwithblameinfo(1, 0, blame_info)

                num_blamed += 1

            # the rest are empty
            else:
                parent_hash = self.rpc[FULLNODE0].generate_block_with_parent(parent_hash=parent_hash)

            # TODO: generate blamed blocks with txs in them (overlap)

        # generate a pivot chain section where we might not be able to decide blaming
        # in this section, all headers will have blame=1
        # odd-numbered blocks are incorrect, even-numbered blocks are correct
        for _ in range(0, BLAMED_SECTION_LENGTH):
            blame_info = {}
            blame_info['blame'] = "0x1"
            parent_hash = self.nodes[FULLNODE0].test_generateblockwithblameinfo(1, 0, blame_info)

        num_blamed += BLAMED_SECTION_LENGTH // 2

        # mine some more blocks to keep blame check offset
        for _ in range(0, BLAMED_SECTION_LENGTH):
            parent_hash = self.rpc[FULLNODE0].generate_custom_block(parent_hash=parent_hash, txs=[], referee=[])

        # check if all txs have been executed successfully
        for hash in hashes:
            receipt = self.rpc[FULLNODE0].get_transaction_receipt(hash)
            assert_equal(receipt["outcomeStatus"], "0x0")

        length = NORMAL_CHAIN_LENGTH + 2 * BLAMED_SECTION_LENGTH
        self.log.info(f"Generated {length} blocks with {num_events} events and {num_blamed} incorrect blocks")


if __name__ == "__main__":
    LightSyncTest().main()
