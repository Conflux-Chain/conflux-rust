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


class AutoDiscovery(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        bootnode = self.nodes[0]
        extra_args0 = ["--enable-discovery", "true", "--node-table-timeout", "1", "--node-table-promotion-timeout", "15"]
        self.start_node(0, extra_args = extra_args0)
        bootnode_id = "cfxnode://{}@{}:{}".format(bootnode.key[2:], bootnode.ip, bootnode.port)
        extra_args = ["--bootnodes", bootnode_id, "--enable-discovery", "true", "--node-table-timeout", "1", "--node-table-promotion-timeout", "15"]
        self.start_time = datetime.datetime.now()
        for i in range(1, self.num_nodes):
            self.start_node(i, extra_args=extra_args)

    def run_test(self):
        self.log.info("Test AutoDiscovery") 
        wait_until(lambda: [len(i.getpeerinfo()) for i in self.nodes].count(self.num_nodes - 1) == self.num_nodes)
        sec = (datetime.datetime.now() - self.start_time).total_seconds()
        assert_greater_than_or_equal(sec, 15)
        self.log.info("Passed after running " + str(sec) + " seconds")


if __name__ == "__main__":
    AutoDiscovery().main()
