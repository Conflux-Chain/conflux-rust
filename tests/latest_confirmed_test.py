#!/usr/bin/env python3
"""An example functional test
"""

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from conflux.rpc import RpcClient


class LatestConfirmedTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        time.sleep(7)
        client = RpcClient(self.nodes[0])
        genesis = self.nodes[0].best_block_hash()
        self.log.info(genesis)
        genesis_epoch = client.epoch_number(client.EPOCH_LATEST_CONFIRMED)
        assert_equal(genesis_epoch, 0)

        # generate blocks in 0.5 sec interval like default
        for i in range(0, 160):
            self.nodes[0].generate_empty_blocks(1)
            time.sleep(0.5)
            last_mined = client.epoch_number(client.EPOCH_LATEST_MINED)
            confirmed = client.epoch_number(client.EPOCH_LATEST_CONFIRMED)
            self.log.info("Mined epoch: " + str(last_mined) + " Confirmed epoch: " + str(confirmed))
            # This is a very loose bound given the default parameter for Conflux.
            # If we change consensus/confirmation related parameters, this needs to be
            # changed as well.
            assert( last_mined <= 70 or last_mined - confirmed > 70 )
            assert( last_mined - confirmed < 100 )

if __name__ == '__main__':
    LatestConfirmedTest().main()
