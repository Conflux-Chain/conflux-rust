#!/usr/bin/env python3
import os
import sys
import time
import random
sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError
from test_framework.util import sync_blocks, connect_nodes, connect_sample_nodes, assert_equal, assert_blocks_valid, \
    wait_until
from conflux.rpc import RpcClient

class SyncCheckpointTests(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.conf_parameters = {
            "dev_snapshot_epoch_count": "10",
            "adaptive_weight_beta": "1",
            "timer_chain_block_difficulty_ratio": "2",
            "timer_chain_beta": "6",
            "era_epoch_count": "50",
            "chunk_size_byte": "1000",
            "anticone_penalty_ratio": "5",
            # Make sure checkpoint synchronization is triggered during phase change.
            "dev_allow_phase_change_without_peer": "false",
            # Disable pos reference because pow blocks are generated too fast.
            "pos_reference_enable_height": "10000",
            "cip1559_transition_height": "10000",
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
        num_blocks = 200
        snapshot_epoch = 150

        # Generate checkpoint on node[0]
        archive_node_client = RpcClient(self.nodes[0])
        self.genesis_nonce = archive_node_client.get_nonce(archive_node_client.GENESIS_ADDR)
        blocks_in_era = []
        for i in range(num_blocks):
            txs = self._generate_txs(0, random.randint(50, 100))
            block_hash = archive_node_client.generate_block_with_fake_txs(txs)
            if i >= snapshot_epoch:
                blocks_in_era.append(block_hash)
        sync_blocks(self.nodes[:-1])
        self.log.info("All archive nodes synced")

        # Start node[full_node_index] as full node to sync checkpoint
        # Change phase from CatchUpSyncBlockHeader to CatchUpCheckpoint
        # only when there is at least one connected peer.
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
        assert full_node_client.epoch_number() >= snapshot_epoch
        wait_until(lambda: full_node_client.epoch_number() == archive_node_client.epoch_number() and
                   full_node_client.epoch_number("latest_state") == archive_node_client.epoch_number("latest_state"))
        # We have snapshot_epoch for state execution but
        # don't offer snapshot_epoch for Rpc clients.
        for i in range(1, snapshot_epoch + 1):
            try:
                full_node_client.get_balance(full_node_client.GENESIS_ADDR, full_node_client.EPOCH_NUM(i))
                raise AssertionError("should not have state for epoch {}".format(i))
            except ReceivedErrorResponseError as e:
                assert "State for epoch" in e.response.message
                assert "does not exist" in e.response.message

        # Wait for execution to complete.
        time.sleep(1)

        # There should be states after checkpoint
        idx = 0
        for i in range(snapshot_epoch + 1, full_node_client.epoch_number() - 3):
            full_balance = full_node_client.get_balance(full_node_client.GENESIS_ADDR, full_node_client.EPOCH_NUM(i))
            archive_balance = archive_node_client.get_balance(archive_node_client.GENESIS_ADDR, archive_node_client.EPOCH_NUM(i))
            assert_equal(full_balance, archive_balance)
            executed_info1 = self.nodes[full_node_index].test_getExecutedInfo(blocks_in_era[idx])
            executed_info2 = self.nodes[0].test_getExecutedInfo(blocks_in_era[idx])
            assert_equal(executed_info1, executed_info2)
            idx += 1

        # Blocks within execution defer (5 epochs) and reward_defer (12 epochs) do not have state_valid
        available_blocks = blocks_in_era[:-17]
        assert_blocks_valid(self.nodes[:-1], available_blocks)
        assert_blocks_valid(self.nodes[-1:], available_blocks)


if __name__ == "__main__":
    SyncCheckpointTests().main()
