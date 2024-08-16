import os, sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from conflux.utils import priv_to_addr
import eth_utils
from test_framework.util import *

class PosRegisterTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["hydra_transition_height"] = 10
        self.conf_parameters["hydra_transition_number"] = 10
        self.conf_parameters["sigma_fix_transition_number"] = 1000

    def run_test(self):
        client0 = RpcClient(self.nodes[0])
        client1 = RpcClient(self.nodes[1])
        client2 = RpcClient(self.nodes[2])
        client3 = RpcClient(self.nodes[3])

        priv0 = "1" * 64
        priv1 = "2" * 64
        priv2 = "3" * 64
        priv3 = "4" * 64

        client0.generate_empty_blocks(30)
        pos_identifier0, priv_key0 = client0.wait_for_pos_register(priv_key=priv0, legacy=True)
        _, priv_key1 = client1.wait_for_pos_register(priv_key=priv1, legacy=False, should_fail=True)

        client0.generate_empty_blocks(1000)
        pos_identifier2, priv_key2 = client2.wait_for_pos_register(priv_key=priv2, legacy=False)
        client3.wait_for_pos_register(priv_key=priv3, legacy=True, should_fail=True)

        self.log.info("Done")

        pos_account1 = client0.pos_get_account(pos_identifier0)
        pos_account2 = client0.pos_get_account_by_pow_address(eth_utils.encode_hex(priv_to_addr(priv_key0)))
        assert_equal(pos_account1["address"], pos_account2["address"])
        assert_equal(pos_account1["status"], pos_account2["status"])


        pos_account1 = client2.pos_get_account(pos_identifier2)
        pos_account2 = client2.pos_get_account_by_pow_address(eth_utils.encode_hex(priv_to_addr(priv_key2)))
        assert_equal(pos_account1["address"], pos_account2["address"])
        assert_equal(pos_account1["status"], pos_account2["status"])

        pos_account = client1.pos_get_account_by_pow_address(eth_utils.encode_hex(priv_to_addr(priv_key1)))
        assert_equal(pos_account["address"], "0x0000000000000000000000000000000000000000000000000000000000000000")
        assert_equal(pos_account["status"]["availableVotes"], "0x0")


if __name__ == "__main__":
    PosRegisterTest().main()