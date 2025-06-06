#!/usr/bin/env python3
import os
import sys

sys.path.insert(1, os.path.dirname(sys.path[0]))

from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import DefaultNode
from test_framework.util import wait_until
from conflux.rpc import RpcClient

class SessionIpLimitTests(ConfluxTestFramework):
    def __init__(self, ip_limit_config: str, num_peers: int):
        self.ip_limit_config = ip_limit_config
        self.num_peers = num_peers
        ConfluxTestFramework.__init__(self)

    def set_test_params(self):
        self.num_nodes = 1

        self.conf_parameters = {
            "session_ip_limits": "\"{}\"".format(self.ip_limit_config)
        }

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        genesis = self.nodes[0].cfx_getBlockByEpochNumber("0x0", False)["hash"]
        peers = [DefaultNode(genesis) for _ in range(self.num_peers)]
        for p in peers:
            self.nodes[0].add_p2p_connection(p)

        # One peer will be refused due to IP limit
        wait_until(lambda: [p.had_status for p in peers].count(False) == 1, timeout=3)
        assert len(RpcClient(self.nodes[0]).get_peers()) == self.num_peers - 1
        for p in peers:
            if not p.had_status:
                wait_until(lambda: p.is_connected == False, timeout=3)

if __name__ == "__main__":
    # 1 node for a single IP address
    SessionIpLimitTests("1,8,4,2", 2).main()