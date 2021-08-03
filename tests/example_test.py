#!/usr/bin/env python3
"""An example functional test
"""
import time

from conflux.utils import int_to_hex
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        # self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 / 2)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        # self.conf_parameters["log_level"] = '"trace"'

    def setup_network(self):
        self.setup_nodes(is_consortium=True, genesis_nodes=3)
        connect_sample_nodes(self.nodes, self.log, latency_max=0)
        sync_blocks(self.nodes)

    def run_test(self):
        time.sleep(2)
        genesis = self.nodes[0].best_block_hash()
        self.log.info(genesis)

        self.nodes[0].generate_empty_blocks(1)
        assert (self.nodes[0].getblockcount() == 2)

        latest_pos_ref = self.latest_pos_ref()
        for _ in range(300):
            # Generate enough PoW block for PoS to progress
            self.nodes[0].generate_empty_blocks(60)
            # Leave some time for PoS to reach consensus
            time.sleep(3)
            self.nodes[0].generate_empty_blocks(1)
            new_pos_ref = self.latest_pos_ref()
            assert_ne(latest_pos_ref, new_pos_ref)
        # assert (self.nodes[0].getblockcount() == 6002)

    def latest_pos_ref(self):
        best_hash = self.nodes[0].best_block_hash()
        block = self.nodes[0].cfx_getBlockByHash(best_hash, False)
        return block["posReference"]

if __name__ == '__main__':
    ExampleTest().main()
