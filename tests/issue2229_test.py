#!/usr/bin/env python3

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *

class Issue2229(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

        self.conf_parameters["generate_tx_period_us"] = "100000"
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["era_epoch_count"] = "100"
        self.conf_parameters["dev_snapshot_epoch_count"] = "25"

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

    def run_test(self):
        # check in current era
        block = self.rpc.block_by_epoch("latest_mined")
        assert_ne(block["blockNumber"], None)

        # create a few new eras
        parent_hash = block["hash"]

        for _ in range(500):
            parent_hash = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash

        # check in old era
        block = self.rpc.block_by_hash(block["hash"])
        assert_ne(block["blockNumber"], None) # <<

        self.log.info("Pass")

if __name__ == "__main__":
    Issue2229().main()
