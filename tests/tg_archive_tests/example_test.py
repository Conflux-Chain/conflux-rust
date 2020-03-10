#!/usr/bin/env python3
"""An example functional test
"""

import time, sys, os

sys.path.insert(1, os.path.dirname(sys.path[0]))
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import sync_blocks, connect_nodes, connect_sample_nodes, assert_equal


class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.conf_parameters = {
            "log_level": "\"debug\"",
            "is_consortium": "true",
            "enable_state_expose": "true",
            "era_epoch_count": 100,
            "dev_snapshot_epoch_count": 50,
        }

    def setup_network(self):
        self.add_nodes(self.num_nodes, is_consortium=True)
        for i in range(self.num_nodes):
            self.start_node(i, ["--tg_archive"], phase_to_wait=None)
        connect_sample_nodes(self.nodes, self.log, latency_max=1)

    def run_test(self):
        time.sleep(7)
        genesis = self.nodes[0].best_block_hash()
        self.log.info("genesis: {}".format(genesis))


if __name__ == '__main__':
    ExampleTest().main()
