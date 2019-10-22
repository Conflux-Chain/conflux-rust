#!/usr/bin/env python3
import os
import sys
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
            "era_epoch_count": "50",
            "era_checkpoint_gap": "50",
        }

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0)

    def run_test(self):
        num_blocks = 200
        checkpoint_epoch = 100

        # Generate checkpoint on node[0]
        client = RpcClient(self.nodes[0])
        genesis_nonce = client.get_nonce(client.GENESIS_ADDR)
        for _ in range(num_blocks):
            tx = client.new_tx(nonce=genesis_nonce)
            tx_hash = client.send_tx(tx)
            assert tx_hash == tx.hash_hex()
            genesis_nonce += 1
            client.generate_block(100)

        # Start node[1] as full node to sync checkpoint
        # Change phase from CatchUpSyncBlockHeader to CatchUpCheckpoint
        # only when there is at least one connected peer.
        self.start_node(1, ["--full"], phase_to_wait=None)
        connect_nodes(self.nodes, 1, 0)

        # FIXME full node issue that hang at phase CatchUpRecoverBlockFromDbPhase
        self.nodes[1].wait_for_phase(["CatchUpRecoverBlockFromDbPhase", "NormalSyncPhase"])

        sync_blocks(self.nodes)

        client = RpcClient(self.nodes[1])
        
        # FIXME conflux panics
        # At epoch 1, block header exists while body not synchronized
        # print(client.block_by_epoch(client.EPOCH_NUM(1)))

        # There is no state from epoch 1 to checkpoint_epoch
        # Note, state of genesis epoch always exists
        assert client.epoch_number() >= checkpoint_epoch
        for i in range(1, checkpoint_epoch):
            try:
                client.get_balance(client.GENESIS_ADDR, client.EPOCH_NUM(i))
                raise AssertionError("should be not state for epoch {}".format(i))
            except ReceivedErrorResponseError as e:
                assert "State for epoch" in e.response.message
                assert "does not exist" in e.response.message

        # State should exist at checkpoint
        client.get_balance(client.GENESIS_ADDR, client.EPOCH_NUM(checkpoint_epoch))

        # FIXME conflux hang/panics at phase CatchUpRecoverBlockFromDbPhase
        # There should be states after checkpoint
        # for i in range(checkpoint_epoch + 1, client.epoch_number() + 1):
        #     client.get_balance(client.GENESIS_ADDR, client.EPOCH_NUM(i))

if __name__ == "__main__":
    SyncCheckpointTests().main()
