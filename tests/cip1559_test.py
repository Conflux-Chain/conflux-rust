from conflux.rpc import RpcClient
from test_framework.util import (
    assert_equal,
)
from decimal import Decimal
from typing import Literal

from cfx_account import Account as CfxAccount
from cfx_account.signers.local import LocalAccount as CfxLocalAccount

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import generate_blocks_for_base_fee_manipulation, assert_correct_fee_computation_for_core_tx

CORE_BLOCK_GAS_TARGET = 270000
BURNT_RATIO = 0.5
MIN_NATIVE_BASE_PRICE = 10000

class CIP1559Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["min_native_base_price"] = MIN_NATIVE_BASE_PRICE
        self.conf_parameters["next_hardfork_transition_height"] = 1
        self.conf_parameters["next_hardfork_transition_number"] = 1
        

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

    # acct should have cfx
    def change_base_fee(self, acct: CfxLocalAccount=None, block_count=10, tx_per_block=4, gas_per_tx=13500000):
        if acct is None:
            acct = self.init_acct_with_cfx()
        generate_blocks_for_base_fee_manipulation(self.rpc, acct, block_count, tx_per_block, gas_per_tx)

            
    def test_block_base_fee_change(self, acct: CfxLocalAccount, epoch_to_test:int, tx_per_block=4, gas_per_tx=13500000):
        starting_epoch = self.rpc.epoch_number()
        self.change_base_fee(acct, epoch_to_test, tx_per_block, gas_per_tx)
        expected_base_fee_change_delta_rate = self.get_expected_base_fee_change_delta_rate(tx_per_block * gas_per_tx, 27000000)

        for i in range(starting_epoch+1, self.rpc.epoch_number()):
            expected_current_base_fee = self.rpc.base_fee_per_gas(i-1) + int(self.rpc.base_fee_per_gas(i-1) * expected_base_fee_change_delta_rate)
            assert_equal(self.rpc.base_fee_per_gas(i), expected_current_base_fee)

    
    def get_expected_base_fee_change_delta_rate(self, sum_tx_gas_limit: int, block_target_gas_limit: int = None) -> Decimal:
        if block_target_gas_limit is None:
            block_target_gas_limit = CORE_BLOCK_GAS_TARGET
        BASE_FEE_MAX_CHANGE_DENOMINATOR = 8
        return ((sum_tx_gas_limit-block_target_gas_limit) / Decimal(block_target_gas_limit)) / BASE_FEE_MAX_CHANGE_DENOMINATOR

    # default to 1000 CFX
    def init_acct_with_cfx(self, drip: int=10**21) -> CfxLocalAccount:
        self.rpc.send_tx(
            self.rpc.new_tx(
                receiver=(acct:=CfxAccount.create()).address,
                value=drip,
                gas_price=max(self.rpc.base_fee_per_gas()*2,MIN_NATIVE_BASE_PRICE) # avoid genisis zero gas price
            ),
            True,
        )
        return acct
    
    def get_gas_charged(self, tx_hash: str) -> int:
        gas_limit = int(self.rpc.get_tx(tx_hash)["gas"], 16)
        gas_used = int(self.rpc.get_transaction_receipt(tx_hash)["gasUsed"], 16)
        return max(int(3/4*gas_limit), gas_used)


    def test_balance_change(self, acct: CfxLocalAccount):
        acct_balance = self.rpc.get_balance(acct.address)
        h = self.rpc.send_tx(
            self.rpc.new_typed_tx(
                priv_key=acct.key.hex(),
                receiver=CfxAccount.create().address,
                max_fee_per_gas=self.rpc.base_fee_per_gas(),
                max_priority_fee_per_gas=self.rpc.base_fee_per_gas(),
                value=100,
            ),
            wait_for_receipt=True,
        )
        receipt = self.rpc.get_transaction_receipt(h)
        acct_new_balance = self.rpc.get_balance(acct.address)
        assert_equal(acct_new_balance, acct_balance - int(receipt["gasFee"], 16) - 100)
        
    # this tests the case for pivot blocks
    # as for non-pivot blocks, the tests are in ./cip137_test.py
    def test_max_fee_not_enough_for_current_base_fee(self):
        self.change_base_fee(block_count=10)
        initial_base_fee = self.rpc.base_fee_per_gas()
        
        self.log.info(f"initla base fee: {initial_base_fee}")
        
        # 112.5% ^ 10
        self.change_base_fee(block_count=10)
        self.log.info(f"increase base fee by 112.5% ^ 10")
        self.log.info(f"new base fee: {self.rpc.base_fee_per_gas()}")
        assert self.rpc.base_fee_per_gas() > initial_base_fee
        self.log.info(f"sending new transaction with max_fee_per_gas: {initial_base_fee}")
        # as the transaction's max fee per gas is not enough for current base fee,
        # the transaction will become pending until the base fee drops
        # we will observe the base fee of the block the transaction is in
        h = self.rpc.send_tx(
            self.rpc.new_typed_tx(
                receiver=CfxAccount.create().address,
                max_fee_per_gas=initial_base_fee,
            ),
            wait_for_receipt=True,
        )
        
        tx_base_fee = self.rpc.base_fee_per_gas(self.rpc.get_transaction_receipt(h)["epochNumber"])
        self.log.info(f"epoch base fee for transaction accepted: {tx_base_fee}")
        assert tx_base_fee <= initial_base_fee
    
    def test_type_2_tx_fees(self):
        
        assert_correct_fee_computation_for_core_tx(self.rpc, self.rpc.send_tx(
            self.rpc.new_typed_tx(
                receiver=CfxAccount.create().address,
                max_fee_per_gas=self.rpc.base_fee_per_gas(),
                max_priority_fee_per_gas=self.rpc.base_fee_per_gas(),
            ),
            wait_for_receipt=True,
        ))
        assert_correct_fee_computation_for_core_tx(self.rpc, self.rpc.send_tx(
            self.rpc.new_typed_tx(
                receiver=CfxAccount.create().address,
                max_fee_per_gas=self.rpc.base_fee_per_gas(),
                max_priority_fee_per_gas=0,
            ),
            wait_for_receipt=True,
        ))
        self.test_balance_change(self.init_acct_with_cfx())

    def test_balance_not_enough_for_base_fee(self):
        # ensuring acct does not have enough balance to pay for base fee
        initial_value = 21000*(MIN_NATIVE_BASE_PRICE-1)
        acct = self.init_acct_with_cfx(initial_value)
        block = self.rpc.generate_custom_block(parent_hash=self.rpc.block_by_epoch("latest_mined")["hash"], referee=[], txs=[
            self.rpc.new_typed_tx(value=0, gas=21000, priv_key=acct.key.hex())
        ])
        self.rpc.generate_blocks(20, 5)
        # self.
        # h = self.rpc.send_tx(
        #     self.rpc.new_typed_tx(
        #         priv_key=acct.key.hex(),
        #         max_fee_per_gas=self.rpc.base_fee_per_gas(),
        #         max_priority_fee_per_gas=self.rpc.base_fee_per_gas(),
        #         value=0,
        #     ),
        #     wait_for_receipt=True,
        # )
        tx_data = self.rpc.block_by_hash(block, True)["transactions"][0]
        tx_receipt = self.rpc.get_transaction_receipt(tx_data["hash"])
        gas_fee = int(tx_receipt["gasFee"],16)
        assert_equal(gas_fee, initial_value)
        assert_equal(tx_data["status"],"0x1")
        # account balance is all consumed
        assert_equal(self.rpc.get_balance(acct.address),0)

    # two cases to test based on balance enough for max priority fee per gas
    # maxPriorityFeePerGas = maxFeePerGas <- will fail because balance is not enough for effective_gas_price * gas_charged
    # maxPriorityFeePerGas = 0 <- succeed
    def test_balance_enough_for_base_fee_but_not_for_max_fee_per_gas(self, priority_fee_setting: Literal["MAX", "ZERO"]):
        # ensuring acct does not have enough balance to pay for base fee
        self.log.info(f"current base fee: {self.rpc.base_fee_per_gas()}")
        assert_equal(self.rpc.base_fee_per_gas(), MIN_NATIVE_BASE_PRICE)
        # allow extra 1 priority fee
        initial_value = 21000*(MIN_NATIVE_BASE_PRICE+1)
        acct = self.init_acct_with_cfx(initial_value)
        max_fee_per_gas = MIN_NATIVE_BASE_PRICE+2
        max_priority_fee: int
        if priority_fee_setting == "MAX":
            max_priority_fee = max_fee_per_gas
        elif priority_fee_setting == "ZERO":
            max_priority_fee = 0
        block = self.rpc.generate_custom_block(parent_hash=self.rpc.block_by_epoch("latest_mined")["hash"], referee=[], txs=[
            self.rpc.new_typed_tx(value=0, gas=21000, priv_key=acct.key.hex(), max_fee_per_gas=max_fee_per_gas, max_priority_fee_per_gas=max_priority_fee)
        ])
        self.rpc.generate_blocks(20, 5)

        tx_data = self.rpc.block_by_hash(block, True)["transactions"][0]
        assert_correct_fee_computation_for_core_tx(self.rpc, tx_data["hash"], BURNT_RATIO)

        if priority_fee_setting == "MAX":
            # extra test to assert gas fee equal to all of the balance
            tx_receipt = self.rpc.get_transaction_receipt(tx_data["hash"])
            gas_fee = int(tx_receipt["gasFee"],16)
            assert_equal(gas_fee, initial_value)


    def run_test(self):
        self.rpc.generate_blocks(5)
        
        # test fee increasing
        self.test_block_base_fee_change(self.init_acct_with_cfx(), 20, 4, 13500000)
        self.test_block_base_fee_change(self.init_acct_with_cfx(), 20, 6, 8000000)
        self.test_block_base_fee_change(self.init_acct_with_cfx(), 20, 3, 13500000)
        # note: as min base fee is provided, we use less epochs
        self.test_block_base_fee_change(self.init_acct_with_cfx(), 10, 1, 13500000)
        self.test_block_base_fee_change(self.init_acct_with_cfx(), 10, 2, 10000000)

        self.test_type_2_tx_fees()
        self.test_max_fee_not_enough_for_current_base_fee()
        self.test_balance_not_enough_for_base_fee()
        self.test_balance_enough_for_base_fee_but_not_for_max_fee_per_gas("ZERO")
        self.test_balance_enough_for_base_fee_but_not_for_max_fee_per_gas("MAX")


if __name__ == "__main__":
    CIP1559Test().main()
