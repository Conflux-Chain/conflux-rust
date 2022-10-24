import os, sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework


class PosRegisterTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["hydra_transition_height"] = 10
        self.conf_parameters["hydra_transition_number"] = 10
        self.conf_parameters["sigma_fix_transition_number"] = 100

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
        client0.wait_for_pos_register(priv_key=priv0, legacy=True)
        client1.wait_for_pos_register(priv_key=priv1, legacy=False, should_fail=True)

        client0.generate_empty_blocks(80)
        client2.wait_for_pos_register(priv_key=priv2, legacy=False)
        client3.wait_for_pos_register(priv_key=priv3, legacy=True, should_fail=True)

        self.log.info("Done")

if __name__ == "__main__":
    PosRegisterTest().main()