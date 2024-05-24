from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.contracts import ConfluxTestFrameworkForContract, BASE
from test_framework.util import *
from test_framework.mininode import *

from os.path import dirname, realpath, join

CFX = 10 ** 18

class CIP97Test(ConfluxTestFrameworkForContract):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 1
        self.conf_parameters["dao_vote_transition_number"] = 100
        self.conf_parameters["hydra_transition_number"] = 90
        self.conf_parameters["cancun_opcodes_transition_number"] = 99999999

    def run_test(self):
        priv = default_config["GENESIS_PRI_KEY"]
        sender = encode_hex(priv_to_addr(priv))
        staking = self.internal_contract("Staking").functions

        def get_current_epoch():
            return int(self.rpc.cfx_getBlockByEpochNumber("latest_mined", False)["epochNumber"], 16)
        
        def deposit():
            receipt = staking.deposit(1 * BASE).cfx_transact()
            return int(receipt["gasUsed"], 16)
        
        def withdraw():
            receipt = staking.withdraw(int(1.1 * BASE)).cfx_transact()
            return int(receipt["gasUsed"], 16)

        for i in range(5):
            self.log.debug(f"deposit {i}")
            deposit()

        old_withdraw_gas = withdraw()
        assert_equal(len(self.client.get_deposit_list(sender)), 4)

        current_epoch = get_current_epoch()
        if current_epoch < 100:
            self.client.generate_blocks(110 - current_epoch)
        wait_until(lambda: get_current_epoch() > 100, timeout=20)

        old_deposit_gas = deposit()
        assert_equal(len(self.client.get_deposit_list(sender)), 5)

        new_withdraw_gas = withdraw()
        assert_equal(len(self.client.get_deposit_list(sender)), 0)

        new_deposit_gas = deposit()
        assert_equal(len(self.client.get_deposit_list(sender)), 0)

        assert_equal(old_deposit_gas - new_deposit_gas, 40000)
        assert_equal(old_withdraw_gas - new_withdraw_gas, 49600)


if __name__ == "__main__":
    CIP97Test().main()
