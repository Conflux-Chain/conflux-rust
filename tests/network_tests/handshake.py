#!/usr/bin/env python3
import os
import sys

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import DefaultNode, network_thread_start
from test_framework.util import wait_until, connect_nodes

class HandshakeTests(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        # mininode handshake
        peer = DefaultNode()
        self.nodes[0].add_p2p_connection(peer)
        network_thread_start()
        wait_until(lambda: peer.had_status, timeout=3)

        # full node handshake
        connect_nodes(self.nodes, 0, 1)

if __name__ == "__main__":
    HandshakeTests().main()