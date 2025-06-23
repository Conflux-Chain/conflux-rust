#!/usr/bin/env python3
import os
import sys
import time
import random

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError
from test_framework.util import sync_blocks, connect_nodes, connect_sample_nodes, assert_equal, wait_until
from conflux.rpc import RpcClient

class SyncCheckpointTests(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.conf_parameters = {
            "dev_snapshot_epoch_count": "200",
            "adaptive_weight_beta": "1",
            "timer_chain_block_difficulty_ratio": "2",
            "timer_chain_beta": "6",
            "era_epoch_count": "1000",
            "chunk_size_byte": "1000",
            "anticone_penalty_ratio": "5",
            # Make sure checkpoint synchronization is triggered during phase change.
            "dev_allow_phase_change_without_peer": "false",
            # Disable pos reference because pow blocks are generated too fast.
            "pos_reference_enable_height": "10000",
            "cip1559_transition_height": "10000",
            "keep_snapshot_before_stable_checkpoint": "false",
        }

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        for i in range(self.num_nodes - 1):
            self.start_node(i, phase_to_wait=None)
        connect_sample_nodes(self.nodes[:-1], self.log, latency_max=1)
        for i in range(self.num_nodes - 1):
            self.nodes[i].wait_for_recovery(["NormalSyncPhase"], 10)

    def _generate_txs(self, peer, num):
        client = RpcClient(self.nodes[peer])
        txs = []
        for _ in range(num):
            addr = client.rand_addr()
            tx_gas = client.DEFAULT_TX_GAS
            tx = client.new_tx(receiver=addr, nonce=self.genesis_nonce, value=21000, gas=tx_gas, data=b'')
            self.genesis_nonce += 1
            txs.append(tx)
        return txs

    def run_test(self):
        num_blocks = 2950
        blocks = []

        # Generate checkpoint
        archive_node_client = RpcClient(self.nodes[0])
        self.genesis_nonce = archive_node_client.get_nonce(archive_node_client.GENESIS_ADDR)
        for i in range(num_blocks):
            txs = self._generate_txs(0, random.randint(1, 2))
            block_hash = archive_node_client.generate_block_with_fake_txs(txs)
            blocks.append(block_hash)
        sync_blocks(self.nodes[:-1])
        self.log.info("All archive nodes synced")

       
        full_node_index = self.num_nodes - 1
        self.start_node(full_node_index, ["--full"], phase_to_wait=None)
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, full_node_index, i)

        self.log.info("Wait for full node to sync, index=%d", full_node_index)
        self.nodes[full_node_index].wait_for_phase(["NormalSyncPhase"], wait_time=240)

        sync_blocks(self.nodes, sync_count=False)

        full_node_client = RpcClient(self.nodes[full_node_index])

        # At epoch 1, block header exists while body not synchronized
        try:
            print(full_node_client.block_by_epoch(full_node_client.EPOCH_NUM(1)))
        except ReceivedErrorResponseError as e:
            assert 'Internal error' == e.response.message

        # There is no state from epoch 1 to snapshot_epoch
        # Note, state of genesis epoch always exists
        wait_until(lambda: full_node_client.epoch_number() == archive_node_client.epoch_number() and
                   full_node_client.epoch_number("latest_state") == archive_node_client.epoch_number("latest_state"))

        # Wait for execution to complete.
        time.sleep(1)

        # There should be states after checkpoint
        for block_hash in blocks[1000: -4]:
            executed_info1 = self.nodes[full_node_index].test_getExecutedInfo(block_hash)
            executed_info2 = self.nodes[0].test_getExecutedInfo(block_hash)
            assert_equal(executed_info1, executed_info2)

        self.nodes[full_node_index].stop_node()
        self.nodes[full_node_index].wait_until_stopped()

        num_blocks = 1500
        for i in range(num_blocks):
            txs = self._generate_txs(0, random.randint(1, 2))
            block_hash = archive_node_client.generate_block_with_fake_txs(txs)
            blocks.append(block_hash)
        sync_blocks(self.nodes[:-1])
        self.log.info("All archive nodes synced")

        self.start_node(full_node_index, None, phase_to_wait=None)
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, full_node_index, i)

        self.log.info("Wait for full node to sync, index=%d", full_node_index)
        self.nodes[full_node_index].wait_for_phase(["NormalSyncPhase"], wait_time=240)

        sync_blocks(self.nodes, sync_count=False)

        wait_until(lambda: full_node_client.epoch_number() == archive_node_client.epoch_number() and
                   full_node_client.epoch_number("latest_state") == archive_node_client.epoch_number("latest_state"))
        time.sleep(1)

        for block_hash in blocks[3000: -4]:
            executed_info1 = self.nodes[full_node_index].test_getExecutedInfo(block_hash)
            executed_info2 = self.nodes[0].test_getExecutedInfo(block_hash)
            assert_equal(executed_info1, executed_info2)


if __name__ == "__main__":
    SyncCheckpointTests().main()
