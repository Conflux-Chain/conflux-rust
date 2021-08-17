#!/usr/bin/env python3
"""An example functional test
"""
import eth_utils
import time

from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        # self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 / 2)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        # self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["dev_allow_phase_change_without_peer"] = "false"

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, genesis_nodes=self.num_nodes - 1)

        # start half of the nodes as archive nodes
        for i in range(self.num_nodes):
            self.start_node(i, phase_to_wait=None)

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log, latency_max=0)
        sync_blocks(self.nodes)
        for node in self.nodes:
            node.wait_for_recovery(["NormalSyncPhase"], 30)

    def run_test(self):
        time.sleep(2)
        client = RpcClient(self.nodes[self.num_nodes - 1])
        _, priv_key = client.wait_for_pos_register()

        genesis = self.nodes[0].best_block_hash()
        self.log.info(genesis)

        self.nodes[0].generate_empty_blocks(1)
        assert (self.nodes[0].getblockcount() == 2)

        latest_pos_ref = self.latest_pos_ref()
        for i in range(150):
            print(i)
            if i == 50:
                client.pos_retire_self()
            if i == 100:
                self.maybe_restart_node(5, 1, 1)
            # Retire node 3 after 5 min.
            # Generate enough PoW block for PoS to progress
            self.nodes[0].generate_empty_blocks(60)
            # Leave some time for PoS to reach consensus
            time.sleep(3)
            self.nodes[0].generate_empty_blocks(1)
            new_pos_ref = self.latest_pos_ref()
            assert_ne(latest_pos_ref, new_pos_ref)

        client.wait_for_unstake(priv_key)
        assert client.get_balance(eth_utils.encode_hex(priv_to_addr(priv_key))) > 100 * 10**18
        # assert (self.nodes[0].getblockcount() == 6002)

    def latest_pos_ref(self):
        best_hash = self.nodes[0].best_block_hash()
        block = self.nodes[0].cfx_getBlockByHash(best_hash, False)
        return block["posReference"]

if __name__ == '__main__':
    ExampleTest().main()
