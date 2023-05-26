#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils
import time

from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.util import *


class PosCommittedBlockTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 - 1)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        self.conf_parameters["pos_round_per_term"] = '10'

    def run_test(self):
        client = RpcClient(self.nodes[0])
        # wait for the first epoch to end
        wait_until(lambda: client.pos_status()["latestVoted"] is not None)
        wait_until(lambda: int(client.pos_status()["latestCommitted"], 0) >= 8)
        self.log.info("wait for empty rounds")
        self.stop_node(2)
        self.stop_node(3)
        time.sleep(5)
        self.start_node(2)
        self.start_node(3)
        self.log.info("restarts")
        # wait for the next epoch
        wait_until(lambda: int(client.pos_status()["epoch"], 0) == 2)
        parent = client.pos_get_block(2)["hash"]
        for v in range(3, 11):
            b = client.pos_get_block(v)
            assert_equal(b["parentHash"], parent)
            parent = b["hash"]
        wait_until(lambda: int(client.pos_status()["epoch"], 0) == 3)
        parent = client.pos_get_block(11)["hash"]
        for v in range(12, 21):
            b = client.pos_get_block(v)
            assert_equal(b["parentHash"], parent)
            parent = b["hash"]
        wait_until(lambda: client.pos_get_block(21) is not None)
        assert_equal(int(client.pos_get_block(21)["epoch"], 0), 3)


if __name__ == '__main__':
    PosCommittedBlockTest().main()
