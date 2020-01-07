#!/usr/bin/env python3
import os
import sys
import random
from jsonrpcclient.exceptions import ReceivedErrorResponseError

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import sync_blocks, connect_nodes
from conflux.rpc import RpcClient

class SyncCheckpointTests(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.conf_parameters = {
            "dev_snapshot_epoch_count": "25",
            "era_epoch_count": "50",
            "era_checkpoint_gap": "50",
        }

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0)
    
    def _generate_txs(self, peer, num):
        client = RpcClient(self.nodes[peer])
        txs = []
        for _ in range(num):
            addr = client.rand_addr()
            tx_gas = client.DEFAULT_TX_GAS
            tx = client.new_tx(receiver=addr, nonce=self.genesis_nonce, value=0, gas=tx_gas, data=b'')
            self.genesis_nonce += 1
            txs.append(tx)
        return txs

    def run_test(self):
        num_blocks = 200
        snapshot_epoch = 100

        # Generate checkpoint on node[0]
        client = RpcClient(self.nodes[0])
        self.genesis_nonce = client.get_nonce(client.GENESIS_ADDR)
        for _ in range(num_blocks):
            txs = self._generate_txs(0, random.randint(5, 10))
            client.generate_block_with_fake_txs(txs)

        # Start node[1] as full node to sync checkpoint
        # Change phase from CatchUpSyncBlockHeader to CatchUpCheckpoint
        # only when there is at least one connected peer.
        self.start_node(1, ["--full"], phase_to_wait=None)
        connect_nodes(self.nodes, 1, 0)

        # FIXME full node issue that hang at phase CatchUpRecoverBlockFromDbPhase
        self.nodes[1].wait_for_phase(["NormalSyncPhase"], wait_time=30)

        sync_blocks(self.nodes, sync_count=False)

        client = RpcClient(self.nodes[1])

        # At epoch 1, block header exists while body not synchronized
        try:
            print(client.block_by_epoch(client.EPOCH_NUM(1)))
        except ReceivedErrorResponseError as e:
            assert 'Internal error' == e.response.message

        # There is no state from epoch 1 to snapshot_epoch
        # Note, state of genesis epoch always exists
        assert client.epoch_number() >= snapshot_epoch
        # We have snapshot_epoch for state execution but
        # don't offer snapshot_epoch for Rpc clients.
        for i in range(1, snapshot_epoch + 1):
            try:
                client.get_balance(client.GENESIS_ADDR, client.EPOCH_NUM(i))
                raise AssertionError("should not have state for epoch {}".format(i))
            except ReceivedErrorResponseError as e:
                assert "State for epoch" in e.response.message
                assert "does not exist" in e.response.message

        # There should be states after checkpoint
        for i in range(snapshot_epoch + 1, client.epoch_number() - 3):
            client.get_balance(client.GENESIS_ADDR, client.EPOCH_NUM(i))

if __name__ == "__main__":
    SyncCheckpointTests().main()
