#!/usr/bin/env python3
import datetime
import time
from rlp.sedes import Binary, BigEndianInt

from conflux import utils
from conflux.utils import encode_hex, bytes_to_int, get_nodeid
from test_framework.blocktools import create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.test_node import TestNode
from test_framework.util import *

class IpLimitedNode(P2PInterface):
    disconnect_reason = None

    def on_disconnect(self, disconnect):
        self.close()
        self.disconnect_reason = disconnect.reason

class AutoDiscovery(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # node 0:     boot node
        # node 1,2,3: nodes with IP limitation disabled
        # node 4:     node with IP limitation enabled
        self.num_nodes = 5

    def discovery_args(self):
        return ["--enable-discovery", "true", "--node-table-timeout", "1", "--node-table-promotion-timeout", "15"]

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        # init boot node: 0
        self.bootnode = self.nodes[0]
        extra_args = self.discovery_args()
        self.start_node(0, extra_args = extra_args)
        self.bootnode_id = "cfxnode://{}@{}:{}".format(self.bootnode.key[2:], self.bootnode.ip, self.bootnode.port)
        
        # init nodes: 1, 2, 3 (4 is used later)
        extra_args.extend(["--bootnodes", self.bootnode_id])
        self.start_time = datetime.datetime.now()
        for i in range(1, self.num_nodes - 1):
            self.start_node(i, extra_args=extra_args)

    def run_test(self):
        # nodes 0,1,2,3 will auto discover each other
        self.log.info("Test AutoDiscovery")
        wait_until(lambda: [len(i.getpeerinfo()) for i in self.nodes[0:-1]].count(self.num_nodes - 2) == self.num_nodes - 1)
        sec = (datetime.datetime.now() - self.start_time).total_seconds()
        assert_greater_than_or_equal(sec, 15)
        self.log.info("Passed after running " + str(sec) + " seconds")

        self.test_ip_limit()
        
    def test_ip_limit(self):
        self.log.info("Test node number limitation per IP")

        # start node with IP limitation enabled
        self.ip_limited_node = self.nodes[self.num_nodes - 1]
        self.start_node(self.num_nodes - 1, extra_args=("--p2p-nodes-per-ip", "1"))

        # add a dummy peer to ensure IP used in underlying node table.
        self.ip_limited_node.addnode(self.bootnode.key, "127.0.0.1:33333")

        # create a P2P connection, and should be refused because of IP limited during handshake
        p2p = IpLimitedNode()
        self.ip_limited_node.add_p2p_connection(p2p)
        network_thread_start()
        wait_until(lambda: p2p.disconnect_reason == 3, timeout=5)


if __name__ == "__main__":
    AutoDiscovery().main()
