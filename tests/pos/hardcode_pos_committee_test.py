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


class HardcodePosCommitteeTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 - 1)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        self.conf_parameters["pos_round_per_term"] = '10'

    def run_test(self):
        client = RpcClient(self.nodes[0])
        validator_verifier = self.nodes[0].pos_getEpochState("1")["verifier"]
        total_committee = validator_verifier["address_to_validator_info"].copy()
        new_committee = total_committee.copy()
        new_committee.popitem()
        validator_verifier["address_to_validator_info"] = new_committee
        hardcoded_committee = {3: validator_verifier}
        self.stop_nodes()
        for i in range(self.num_nodes):
            set_node_pos_config(self.options.tmpdir, i, hardcoded_epoch_committee=hardcoded_committee)
        self.start_nodes()
        wait_until(lambda: int(client.pos_status()["epoch"], 0) == 3)
        wait_until(lambda: int(client.pos_status()["latestCommitted"], 0) == 21)
        committee = self.nodes[0].pos_getCommittee(int_to_hex(2 * 10 + 1))
        assert_equal(len(committee["currentCommittee"]["nodes"]), 3)

        # Wait and check if the removed account can be elected back.
        wait_until(lambda: int(client.pos_status()["epoch"], 0) == 4, timeout=120)
        wait_until(lambda: int(client.pos_status()["latestCommitted"], 0) == 31)
        committee = self.nodes[0].pos_getCommittee(int_to_hex(3 * 10 + 1))
        assert_equal(len(committee["currentCommittee"]["nodes"]), 4)


if __name__ == '__main__':
    HardcodePosCommitteeTest().main()
