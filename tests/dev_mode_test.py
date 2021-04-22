#!/usr/bin/env python3
"""An example functional test
"""
from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class DevModeTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["mode"] = '"dev"'

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        rpc = RpcClient(self.nodes[0])
        tx = rpc.new_tx()
        tx_hash = rpc.send_tx(tx)
        wait_until(lambda: checktx(self.nodes[0], tx_hash))


if __name__ == '__main__':
    DevModeTest().main()
