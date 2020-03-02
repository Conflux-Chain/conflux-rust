#!/usr/bin/env python3
import os
import sys

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import wait_until

class AutoDiscovery(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.conf_parameters = {
            "discovery_fast_refresh_timeout_ms": "200",
            "discovery_round_timeout_ms": "100",
            "discovery_housekeeping_timeout_ms": "200",
        }

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        # init boot node: 0
        self.bootnode = self.nodes[0]
        extra_args = ["--enable-discovery", "true", "--node-table-timeout-s", "1", "--node-table-promotion-timeout-s", "1"]
        self.start_node(0, extra_args)
        self.bootnode_id = "cfxnode://{}@{}:{}".format(self.bootnode.key[2:], self.bootnode.ip, self.bootnode.port)

        # init nodes: 1, 2, 3
        extra_args.extend(["--bootnodes", self.bootnode_id])
        for i in range(1, self.num_nodes):
            self.start_node(i, extra_args)

    def run_test(self):
        # nodes 0,1,2,3 will auto discover each other
        self.log.info("Test AutoDiscovery")
        wait_until(lambda: [len(i.getpeerinfo()) for i in self.nodes].count(self.num_nodes - 1) == self.num_nodes)
        self.log.info("Passed")

if __name__ == "__main__":
    AutoDiscovery().main()
