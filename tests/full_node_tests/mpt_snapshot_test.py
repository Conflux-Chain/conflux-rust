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
            "use_isolated_db_for_mpt_table": "false",
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
        num_blocks = 2950

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

        self.nodes[node_index].stop_node()
        self.nodes[node_index].wait_until_stopped()

        self.log.info("enable mpt snapshot")
        p = os.path.join(self.options.tmpdir, "node" + str(node_index))
        conf_file = os.path.join(p, "conflux.conf")
        with open(conf_file, "r", encoding="utf8") as f:
            lines = f.readlines()
            conf = {}
            for line in lines:
                idx = line.find("=")
                conf[line[:idx]] = line[idx + 1 :]

        conf["use_isolated_db_for_mpt_table"] = "true"
        os.remove(conf_file)

        with open(conf_file, "w", encoding="utf8") as f:
            for k, v in conf.items():
                f.write("{}={}".format(k, v))

        # check 1
        self.start_node(node_index, None, phase_to_wait=None)

        self.log.info("Wait for full node to sync, index=%d", node_index)
        self.nodes[node_index].wait_for_phase(["NormalSyncPhase"], wait_time=240)

        for _ in range(num_blocks):
            txs = self._generate_txs(0, random.randint(1, 2))
            client1.generate_block_with_fake_txs(txs)

        sync_blocks(self.nodes, timeout=120)

        self.log.info("epoch number %d", client1.epoch_number())
        assert_equal(client1.epoch_number(), client2.epoch_number())

        # check 2
        self.nodes[node_index].stop_node()
        self.nodes[node_index].wait_until_stopped()

        self.start_node(node_index, None, phase_to_wait=None)

        self.log.info("Wait for full node to sync, index=%d", node_index)
        self.nodes[node_index].wait_for_phase(["NormalSyncPhase"], wait_time=240)

        counter = random.randint(500, num_blocks)
        self.log.info("generate blocks %d", counter)
        for _ in range(counter):
            txs = self._generate_txs(1, random.randint(1, 2))
            client2.generate_block_with_fake_txs(txs)

        sync_blocks(self.nodes, timeout=120)

        self.log.info("epoch number %d", client1.epoch_number())
        assert_equal(client1.epoch_number(), client2.epoch_number())

        # check 3
        self.nodes[node_index].stop_node()
        self.nodes[node_index].wait_until_stopped()

        self.start_node(node_index, None, phase_to_wait=None)

        self.log.info("Wait for full node to sync, index=%d", node_index)
        self.nodes[node_index].wait_for_phase(["NormalSyncPhase"], wait_time=240)

        counter = random.randint(500, num_blocks)
        self.log.info("generate blocks %d", counter)
        for _ in range(counter):
            txs = self._generate_txs(1, random.randint(1, 2))
            client2.generate_block_with_fake_txs(txs)

        sync_blocks(self.nodes, timeout=120)

        self.log.info("epoch number %d", client1.epoch_number())
        assert_equal(client1.epoch_number(), client2.epoch_number())


if __name__ == "__main__":
    SyncCheckpointTests().main()
