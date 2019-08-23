#!/usr/bin/env python3
import os
import sys
import time

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import DefaultNode, network_thread_start
from test_framework.util import connect_nodes, get_peer_addr, wait_until
from conflux.rpc import RpcClient

class NodeReputationTests(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4

        # try to create more outgoing connections timely
        self.test_house_keeping_ms = 300

        self.conf_parameters = {
            "discovery_housekeeping_timeout_ms": str(self.test_house_keeping_ms),
        }

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        client0 = RpcClient(self.nodes[0])

        self.test_disconnect_with_failure(client0)
        self.test_disconnect_with_demote(client0)
        self.test_disconnect_with_remove(client0)

    def connect_nodes(self, client0: RpcClient, to_index: int) -> int:
        connect_nodes(self.nodes, 0, to_index)

        node = client0.get_node(self.nodes[to_index].key)

        assert node is not None
        assert node[0] == "trusted"
        assert node[1]["lastConnected"].get("success")
        assert node[1]["lastContact"].get("success")
        token = node[1]["streamToken"]
        assert token is not None

        return token

    def test_disconnect_with_failure(self, client0: RpcClient):
        token = self.connect_nodes(client0, 1)

        assert client0.disconnect_peer(self.nodes[1].key, client0.UPDATE_NODE_OP_FAILURE) == token

        # Node 1 is still in trusted node table, only marked as failure.
        node = client0.get_node(self.nodes[1].key)
        assert node[0] == "trusted"
        assert node[1]["lastConnected"].get("failure")
        assert node[1]["lastContact"].get("failure")
        assert node[1]["streamToken"] == token

        # Node 0 still create outgoing connection to Node 1
        time.sleep((self.test_house_keeping_ms + 100) / 1000)
        assert client0.get_peer(self.nodes[1].key) is not None

    def test_disconnect_with_demote(self, client0: RpcClient):
        token = self.connect_nodes(client0, 2)

        assert client0.disconnect_peer(self.nodes[2].key, client0.UPDATE_NODE_OP_DEMOTE) == token

        # demote to untrusted node table
        node = client0.get_node(self.nodes[2].key)
        assert node[0] == "untrusted"
        assert node[1]["lastConnected"].get("failure")
        assert node[1]["lastContact"].get("failure")
        assert node[1]["streamToken"] == token

        # Node 0 will not create outgoing connection to Node 2
        time.sleep((self.test_house_keeping_ms + 100) / 1000)
        assert client0.get_peer(self.nodes[2].key) is None

    def test_disconnect_with_remove(self, client0: RpcClient):
        token = self.connect_nodes(client0, 3)

        assert client0.disconnect_peer(self.nodes[3].key, client0.UPDATE_NODE_OP_REMOVE) == token

        # On node 0: node 3 is blacklisted, and cannot immediately add it again
        assert client0.get_node(self.nodes[3].key) is None
        self.nodes[0].addnode(self.nodes[3].key, get_peer_addr(self.nodes[3]))
        assert client0.get_node(self.nodes[3].key) is None

        # On node 3: add node 0 as trusted node, so that try to create
        # outgoing connection to node 0.
        client3 = RpcClient(self.nodes[3])
        self.nodes[3].addnode(self.nodes[0].key, get_peer_addr(self.nodes[0]))
        node0 = client3.get_node(self.nodes[0].key)
        assert node0[0] == "trusted"

        # Node 3 create more outgoing connection, but it's blacklisted in node 0.
        time.sleep((self.test_house_keeping_ms + 100) / 1000)
        peer0 = client3.get_peer(self.nodes[0].key)
        # refused during handshake or not handshaked yet
        assert peer0 is None or peer0["caps"] is None

if __name__ == "__main__":
    NodeReputationTests().main()