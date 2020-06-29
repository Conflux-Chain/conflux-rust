#!/usr/bin/env python3
"""An example functional test
"""
from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import priv_to_addr, encode_hex
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *

ERA_EPOCH_COUNT = 100
# Set it large enough to cover Genesis
ADDITIONAL_SNAPSHOT = 100


"""
This test checks if setting `additional_maintained_snapshot_count` and allow states not deleted.
Since the state maintain is based on stable genesis, but we cannot access its accurate height,
here we do not check if the exact number of maintained state is equal to our configuration.
"""
class StateMaintainTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["era_epoch_count"] = str(ERA_EPOCH_COUNT)
        self.conf_parameters["dev_snapshot_epoch_count"] = str(ERA_EPOCH_COUNT // 2)
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"

        self.conf_parameters["additional_maintained_snapshot_count"] = str(ADDITIONAL_SNAPSHOT)

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        client = RpcClient(self.nodes[0])
        genesis_address = "0x" + encode_hex(priv_to_addr(default_config['GENESIS_PRI_KEY']))
        genesis_balance = default_config["TOTAL_COIN"]
        client.generate_empty_blocks(ERA_EPOCH_COUNT * 10)
        print(client.epoch_number("latest_checkpoint"))
        assert client.epoch_number("latest_checkpoint") > 0
        # Just assert we can still get the balance
        assert_equal(client.get_balance(genesis_address, client.EPOCH_NUM(1)), genesis_balance)

        # Restart to check if the state is persist
        # FIXME: State lower bound is still set to stable genesis after restarting, so the following will fail.

        # self.stop_node(0)
        # self.start_node(0)
        # assert_equal(client.get_balance(genesis_address, client.EPOCH_NUM(1)), genesis_balance)


if __name__ == '__main__':
    StateMaintainTest().main()
