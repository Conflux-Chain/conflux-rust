#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from argparse import ArgumentParser
from remote_simulate import RemoteSimulate
from test_framework.test_framework import OptionHelper

class Experiment(RemoteSimulate):
    def __init__(self):
        self.exp_name = "balance_attack"
        super().__init__()

    def add_options(self, parser:ArgumentParser):
        OptionHelper.add_options(parser, {"nodes_per_host": 1})
        super().add_options(parser)

    def run_test(self):
        # setup monitor to report the current block count periodically
        cur_block_count = self.nodes[0].getblockcount()
        # The monitor will check the block_count of nodes[0]
        monitor_thread = threading.Thread(target=self.monitor, args=(cur_block_count, 100), daemon=True)
        monitor_thread.start()

        # When enable_tx_propagation is set, let conflux nodes generate tx automatically.
        self.init_txgen()
        # We instruct nodes to generate blocks.
        # FIXME: change it to balance attack by StrategyFixedPeerLatency.
        self.generate_blocks_async()

        monitor_thread.join()

        self.log.info("Goodput: {}".format(self.nodes[0].getgoodput()))
        self.wait_until_nodes_synced()

        self.log.info("Best block: {}".format(RpcClient(self.nodes[0]).best_block_hash()))

if __name__ == "__main__":
    Experiment().main()
