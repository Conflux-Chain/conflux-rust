#!/usr/bin/env python3
"""Pivot chain changed during reboot node
1. Node 1 generate chain 1
2. Node 2 generate chain 2, longer than chain 1
3. Node 1, node 2 synced, pivot chain is chain 2
4. Node 1 stoped
5. Node 2 changed pivot chain to chain 1
6. Node 1 start
7. Blocks in node 1 since fork point should be reexecuted
"""

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from conflux.rpc import RpcClient


class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["dev_allow_phase_change_without_peer"] = "false"

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        for i in range(self.num_nodes):
            self.start_node(i, phase_to_wait=None)


    def setup_network(self):
        self.setup_nodes()
        # Make all nodes fully connected, so a crashed archive node can be connected to another
        # archive node to catch up
        connect_sample_nodes(self.nodes, self.log, sample=self.num_nodes - 1)
        sync_blocks(self.nodes)
        for node in self.nodes:
            node.wait_for_recovery(["NormalSyncPhase"], 30)


    def run_test(self):
        client1 = RpcClient(self.nodes[0])
        client2 = RpcClient(self.nodes[1])

        genesis = self.nodes[0].best_block_hash()
        self.log.info("genesis {}".format(genesis))
        self.log.info("Node 1 epoch {}".format(client1.epoch_number()))

        # generate common blocks
        self.nodes[0].test_generateEmptyBlocks(20)
        sync_blocks(self.nodes[0:2])

        e1 = client1.epoch_number()
        e2 = client2.epoch_number()
        self.log.info("Node 1 epoch {}".format(e1))
        self.log.info("Node 2 epoch {}".format(e2))
        assert_equal(e1, 20)
        assert_equal(e2, 20)

        # Disconnect nodes
        disconnect_nodes(self.nodes, 0, 1)

        tx = client1.new_tx()

        # pack tx in node 1
        # pivot chain in node 1
        tx_hash = client1.send_tx(tx)
        self.log.info("Node 1 tx hash {}".format(tx_hash))

        block_hash1 = client1.generate_block(1)
        self.log.info("Node 1 block hash {}".format(block_hash1))

        blocks = self.nodes[0].test_generateEmptyBlocks(6)
        last_block = blocks[-1]

        tx_info = client1.get_tx(tx_hash)
        block_contains_tx1 = tx_info["blockHash"]

        assert_equal(block_contains_tx1, block_hash1)

        self.log.info("Node 1 block info {}".format(client1.block_by_hash(block_hash1, True)))
        self.log.info("Node 1 tx info {}".format(tx_info))
        
        # pack tx in node2
        # pivot chain in node 2
        tx_hash_new = client2.send_tx(tx)
        self.log.info("Node 2 tx hash {}".format(tx_hash_new))
        assert_equal(tx_hash, tx_hash_new)

        block_hash2 = client2.generate_block(1)
        self.log.info("Node 2 block hash {}".format(block_hash2))

        self.nodes[1].test_generateEmptyBlocks(12)

        tx_info = client2.get_tx(tx_hash)
        block_contains_tx2 = tx_info["blockHash"]

        assert_equal(block_contains_tx2, block_hash2)

        self.log.info("Node 2 block info {}".format(client2.block_by_hash(block_hash2, True)))
        self.log.info("Node 2 tx info {}".format(tx_info))

        self.log.info("Node 1 epoch {}".format(client1.epoch_number()))
        self.log.info("Node 2 epoch {}".format(client2.epoch_number()))

        # sync blocks, pivot chain in node 1 changed
        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes[0:2])

        self.log.info("Node 1 epoch {}".format(client1.epoch_number()))
        self.log.info("Node 2 epoch {}".format(client2.epoch_number()))

        b1 = client1.get_tx(tx_hash)["blockHash"]
        b2 = client2.get_tx(tx_hash)["blockHash"]
       
        assert_equal(b1, block_hash2)
        assert_equal(b2, block_hash2)

        self.log.info("==== Stop node 1 ====")
        self.nodes[0].stop_node()
        self.nodes[0].wait_until_stopped()

        # change pivot chain in node 2, must more than 20 (CATCH_UP_EPOCH_LAG_THRESHOLD)
        for i in range(30):
            last_block = client2.generate_block_with_parent(last_block)

        self.log.info("==== Start node 1 ====")
        self.nodes[0].start()
        self.nodes[0].wait_for_rpc_connection()
        self.nodes[0].wait_for_nodeid()
        self.nodes[0].wait_for_recovery(["NormalSyncPhase"], 100)

        self.log.info("Node 1 epoch {}".format(client1.epoch_number()))
        self.log.info("Node 2 epoch {}".format(client2.epoch_number()))

        # pivot chain in node 1 changed
        b1 = client1.get_tx(tx_hash)["blockHash"]
        b2 = client2.get_tx(tx_hash)["blockHash"]
       
        assert_equal(b1, block_hash1)
        assert_equal(b2, block_hash1)


if __name__ == '__main__':
    ExampleTest().main()
