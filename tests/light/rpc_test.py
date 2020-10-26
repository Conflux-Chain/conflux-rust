#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys, random, time
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error, connect_nodes, sync_blocks

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

ERA_EPOCH_COUNT = 100
NUM_BLOCKS = 600
NUM_TXS = 10

class LightRPCTest(ConfluxTestFramework):
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

    def test_cfx_epoch_number(self):
        self.log.info(f"Generating blocks...")
        self.rpc[FULLNODE0].generate_blocks(NUM_BLOCKS)
        sync_blocks(self.nodes)

        self.log.info(f"Checking cfx_epochNumber...")

        earliest = self.rpc[LIGHTNODE].epoch_number("earliest")
        assert_equal(earliest, 0)

        latest_checkpoint = self.rpc[LIGHTNODE].epoch_number("latest_checkpoint")
        assert_greater_than(latest_checkpoint, 0) # make sure it's a meaningful test
        assert_equal(latest_checkpoint, self.rpc[FULLNODE0].epoch_number("latest_checkpoint"))

        # TODO(thegaram): check why latest_confirmed is not the same on light and full nodes
        latest_confirmed = self.rpc[LIGHTNODE].epoch_number("latest_confirmed")
        assert_greater_than(latest_confirmed, 0)

        latest_state = self.rpc[LIGHTNODE].epoch_number("latest_state")
        assert_equal(latest_state, NUM_BLOCKS - 20)

        latest_mined = self.rpc[LIGHTNODE].epoch_number("latest_mined")
        assert_equal(latest_mined, NUM_BLOCKS - 20)

        assert_raises_rpc_error(None, None, self.rpc[LIGHTNODE].epoch_number, hex(NUM_BLOCKS + 20))

        self.log.info(f"Pass -- cfx_epochNumber")

    def test_cfx_get_next_nonce(self):
        self.log.info(f"Generating transactions...")

        address = self.rpc[FULLNODE0].GENESIS_ADDR

        # send some txs to increase the nonce
        for nonce in range(0, NUM_TXS):
            receiver, _ = self.rpc[FULLNODE0].rand_account()
            tx = self.rpc[FULLNODE0].new_tx(receiver=receiver, nonce=nonce)
            self.rpc[FULLNODE0].send_tx(tx, wait_for_receipt=True)

        # make sure we can check the blame for each header
        self.rpc[FULLNODE0].generate_blocks(20)
        sync_blocks(self.nodes)

        self.log.info(f"Checking cfx_getNextNonce results...")

        full_nonce = self.nodes[FULLNODE0].cfx_getNextNonce(address)
        assert_equal(full_nonce, hex(NUM_TXS))

        light_nonce = self.nodes[LIGHTNODE].cfx_getNextNonce(address)
        assert_equal(light_nonce, full_nonce)

        self.log.info(f"Pass -- cfx_getNextNonce")

    def run_test(self):
        self.test_cfx_epoch_number()
        self.test_cfx_get_next_nonce()

if __name__ == "__main__":
    LightRPCTest().main()
