#!/usr/bin/env python3
import os
import sys
import random


sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import sync_blocks, connect_sample_nodes, assert_equal
from conflux.rpc import RpcClient


class SyncCheckpointTests(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
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
            "node_type": "\"archive\"",
            "use_isolated_db_for_mpt_table": "true",
        }

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        for i in range(self.num_nodes):
            self.start_node(i, phase_to_wait=None)
        connect_sample_nodes(self.nodes, self.log, latency_max=1)
        for i in range(self.num_nodes):
            self.nodes[i].wait_for_recovery(["NormalSyncPhase"], 10)

    def _generate_txs(self, peer, num):
        client = RpcClient(self.nodes[peer])
        txs = []
        for _ in range(num):
            addr = client.rand_addr()
            tx_gas = client.DEFAULT_TX_GAS
            tx = client.new_tx(
                receiver=addr,
                nonce=self.genesis_nonce,
                value=21000,
                gas=tx_gas,
                data=b"",
            )
            self.genesis_nonce += 1
            txs.append(tx)
        return txs

    def run_test(self):
        num_blocks = 300

        # Generate checkpoint
        client1 = RpcClient(self.nodes[0])
        node_index = 1
        client2 = RpcClient(self.nodes[node_index])

        self.genesis_nonce = client1.get_nonce(client1.GENESIS_ADDR)

        for _ in range(num_blocks):
            txs = self._generate_txs(0, random.randint(1, 2))
            client1.generate_block_with_fake_txs(txs)
        sync_blocks(self.nodes)
        self.log.info("All nodes synced")

        self.log.info("epoch number %d", client1.epoch_number())
        assert_equal(client1.epoch_number(), client2.epoch_number())

        checkpoint_block_hash = client1.block_by_epoch(hex(200))['hash']
        db_path = "sqlite_" + checkpoint_block_hash[2:]
        rel_path = os.path.join("blockchain_data", "storage_db", "mpt_snapshot", db_path)
        node0_full_path = os.path.join(client1.node.datadir, rel_path)
        node1_full_path = os.path.join(client2.node.datadir, rel_path)

        assert(not os.path.exists(node0_full_path))
        assert(not os.path.exists(node1_full_path))


if __name__ == "__main__":
    SyncCheckpointTests().main()
