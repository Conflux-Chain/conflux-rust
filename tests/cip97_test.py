from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

from os.path import dirname, realpath, join

CFX = 10 ** 18

class CIP97Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["dao_vote_transition_number"] = 100
        self.conf_parameters["hydra_transition_number"] = 90

    def run_test(self):
        rpc = RpcClient(self.nodes[0])
        w3 = web3.Web3()
        start_p2p_connection(self.nodes)
        priv = default_config["GENESIS_PRI_KEY"]
        sender = encode_hex(priv_to_addr(priv))

        def send_tx(tx):
            rpc.send_tx(tx, True)
            self.wait_for_tx([tx], True)

        def send_tx_with_gas_used(tx):
            tx_hash = rpc.send_tx(tx, True)
            receipt = rpc.get_transaction_receipt(tx_hash)
            assert_equal(receipt["outcomeStatus"], "0x0")
            return int(receipt["gasUsed"], 16)

        def get_current_epoch():
            return int(self.nodes[0].cfx_getBlockByEpochNumber("latest_mined", False)["epochNumber"], 16)

        control_contract_file_path = join(dirname(realpath(__file__)),
                                          *"../internal_contract/metadata/Staking.json".split("/"))
        control_contract_dict = json.loads(open(control_contract_file_path, "r").read())
        staking = w3.eth.contract(abi=control_contract_dict["abi"])

        def deposit_tx():
            return rpc.new_contract_tx(receiver="0888000000000000000000000000000000000002",
                                       data_hex=staking.encodeABI(fn_name="deposit", args=[1 * CFX]))

        def withdraw_tx():
            return rpc.new_contract_tx(receiver="0888000000000000000000000000000000000002",
                                       data_hex=staking.encodeABI(fn_name="withdraw", args=[int(1.1 * CFX)]))

        for i in range(5):
            self.log.debug(f"deposit {i}")
            send_tx(deposit_tx())

        tx = withdraw_tx()
        old_withdraw_gas = send_tx_with_gas_used(tx)
        assert_equal(len(rpc.get_deposit_list(sender)), 4)

        current_epoch = get_current_epoch()
        if current_epoch < 100:
            rpc.generate_blocks(110 - current_epoch)
        wait_until(lambda: get_current_epoch() > 100, timeout=20)

        tx = deposit_tx()
        old_deposit_gas = send_tx_with_gas_used(tx)
        assert_equal(len(rpc.get_deposit_list(sender)), 5)

        tx = withdraw_tx()
        new_withdraw_gas = send_tx_with_gas_used(tx)
        assert_equal(len(rpc.get_deposit_list(sender)), 0)

        tx = deposit_tx()
        new_deposit_gas = send_tx_with_gas_used(tx)
        assert_equal(len(rpc.get_deposit_list(sender)), 0)

        assert_equal(old_deposit_gas - new_deposit_gas, 40000)
        assert_equal(old_withdraw_gas - new_withdraw_gas, 49600)


if __name__ == "__main__":
    CIP97Test().main()
