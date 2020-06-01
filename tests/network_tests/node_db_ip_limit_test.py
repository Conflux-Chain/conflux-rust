#!/usr/bin/env python3
import os
import sys

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import DefaultNode
from conflux.rpc import RpcClient

class NodeDatabaseIpLimitTests(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

        self.conf_parameters = {
            "subnet_quota": "2"
        }

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        client = RpcClient(self.nodes[0])

        self.test_same_ip_replace_always(client)
        self.test_subnet_quota(client)

    def test_same_ip_replace_always(self, client: RpcClient):
        n1 = DefaultNode()
        client.add_node(n1.key, "192.168.0.100", 5678)
        assert client.get_node(n1.key) is not None

        n2 = DefaultNode()
        client.add_node(n2.key, "192.168.0.100", 5678)
        assert client.get_node(n1.key) is None
        assert client.get_node(n2.key) is not None

    def test_subnet_quota(self, client: RpcClient):
        n1 = DefaultNode()
        client.add_node(n1.key, "192.168.1.200", 5678)
        assert client.get_node(n1.key) is not None

        n2 = DefaultNode()
        client.add_node(n2.key, "192.168.1.201", 5678)
        assert client.get_node(n2.key) is not None

        n3 = DefaultNode()
        client.add_node(n3.key, "192.168.1.202", 5678)
        assert client.get_node(n3.key) is not None

        # n1 or n2 was evicted when adding n3
        assert [client.get_node(n1.key), client.get_node(n2.key)].count(None) == 1

if __name__ == "__main__":
    NodeDatabaseIpLimitTests().main()