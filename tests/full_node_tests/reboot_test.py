#!/usr/bin/env python3
import os
import sys
import random

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import sync_blocks, connect_nodes, connect_sample_nodes, assert_equal
from conflux.rpc import RpcClient

class SyncCheckpointTests(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.conf_parameters = {
            "dev_snapshot_epoch_count": "100",
            "adaptive_weight_beta": "1",
            "timer_chain_block_difficulty_ratio": "2",
            "timer_chain_beta": "6",
            "era_epoch_count": "500",
            "chunk_size_byte": "1000",
            "anticone_penalty_ratio": "5",
            # Make sure checkpoint synchronization is triggered during phase change.
            "dev_allow_phase_change_without_peer": "false",
            # Disable pos reference because pow blocks are generated too fast.
            "pos_reference_enable_height": "10000",
            "keep_snapshot_before_stable_checkpoint": "false",
            # force recompute with parent snapshot doesn't exist
            "force_recompute_height_during_construct_pivot": "1501",
        }

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        for i in range(self.num_nodes):
            self.start_node(i, phase_to_wait=None)
        connect_sample_nodes(self.nodes, self.log, latency_max=1)
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
        num_blocks = 2200
        snapshot_epoch = 1500

        archive_node_client = RpcClient(self.nodes[0])
        self.genesis_nonce = archive_node_client.get_nonce(archive_node_client.GENESIS_ADDR)
        blocks_in_era = []
        for i in range(num_blocks):
            txs = self._generate_txs(0, random.randint(1, 5))
            block_hash = archive_node_client.generate_block_with_fake_txs(txs)
            if i >= snapshot_epoch:
                blocks_in_era.append(block_hash)
        sync_blocks(self.nodes)
        self.log.info("All archive nodes synced")

        full_node_index = self.num_nodes - 1
        self.nodes[full_node_index].stop_node()
        self.nodes[full_node_index].wait_until_stopped()

        self.start_node(full_node_index, ["--full"], phase_to_wait=None)
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, full_node_index, i)

        full_node_client = RpcClient(self.nodes[full_node_index])

        self.log.info("Wait for full node to sync, index=%d", full_node_index)
        self.nodes[full_node_index].wait_for_phase(["NormalSyncPhase"], wait_time=240)

        for block_hash in blocks_in_era[:-4]:
            executed_info1 = self.nodes[full_node_index].getExecutedInfo(block_hash)
            executed_info2 = self.nodes[0].getExecutedInfo(block_hash)
            assert_equal(executed_info1, executed_info2)


if __name__ == "__main__":
    SyncCheckpointTests().main()
