from typing import Union, Tuple
from conflux.rpc import RpcClient, default_config
from test_framework.util import (
    assert_equal,
)

from cfx_account import Account as CfxAccount
from cfx_account.signers.local import LocalAccount as CfxLocalAccount

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import generate_blocks_for_base_fee_manipulation, generate_single_block_for_base_fee_manipulation

MIN_NATIVE_BASE_PRICE = 10000
BURNT_RATIO = 0.5


class CIP137Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["min_native_base_price"] = MIN_NATIVE_BASE_PRICE

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

    # We need to ensure that the tx in B block
    # B and ending block will be in the same epoch
    #                      ---        ---        ---        ---        ---
    #                  .- | A | <--- | C | <--- | D | <--- | E | <--- | F | <--- ...
    #           ---    |   ---        ---        ---        ---        ---
    # ... <--- | P | <-*                                                .
    #           ---    |   ---                                          .
    #                  .- | B | <........................................
    #                      ---
    # ensures txs to be included in B block and the ending block (e.g. F) base gas price is greater than the specified target_minimum_base_fee (not guaranteed to be the first block)
    # returns the ending block hash
    def construct_non_pivot_block(self, acct: CfxLocalAccount, txs: list, starting_block_hash: str=None, epoch_delta: int=5) -> Tuple[str, str]:
        
        if epoch_delta <=0:
            raise ValueError("epoch_delta must be positive")
        
        if starting_block_hash is None:
            starting_block_hash = self.rpc.block_by_epoch("latest_mined")["hash"]
        
        # create the non-pivot block
        non_pivot_block = self.rpc.generate_custom_block(parent_hash=starting_block_hash, txs=txs, referee=[])
        ending_but_two_block, account_next_nonce = generate_blocks_for_base_fee_manipulation(
            self.rpc, acct, epoch_delta, initial_parent_hash=starting_block_hash
        )
        ending_block, _ = generate_single_block_for_base_fee_manipulation(
            self.rpc, acct, [non_pivot_block], parent_hash=ending_but_two_block, starting_nonce=account_next_nonce
        )
        return non_pivot_block, ending_block
        
    
    
    # TODO: test in pivot block transaction will not be included if burnt_ratio*base_gas_fee_per_gas < max_fee_per_gas < base_gas_fee_per_gas

    # continuously fill transaction in C to F to increase base gas fee for F epoch
    # then transaction in B block will fail
    def run_test(self):

        acct1 = CfxAccount.create()
        acct2 = CfxAccount.create()
        
        # assert self.rpc.base_fee_per_gas() < gas_price_level_1 * burnt_ratio

        # send 1000 CFX to each account
        self.rpc.send_tx(self.rpc.new_tx(receiver=acct1.address, value=10**21, gas_price=MIN_NATIVE_BASE_PRICE), True)
        self.rpc.send_tx(self.rpc.new_tx(receiver=acct2.address, value=10**21, gas_price=MIN_NATIVE_BASE_PRICE), True)
        block_p = self.rpc.block_by_epoch("latest_mined")["hash"]
        
        gas_price_level_1 = MIN_NATIVE_BASE_PRICE
        gas_price_level_2 = self.rpc.base_fee_per_gas() * 10
        
        acct1_txs = [
            self.rpc.new_tx(receiver=self.rpc.rand_addr(), priv_key=acct1.key, nonce=0, gas_price=gas_price_level_2), # expected to succeed
            self.rpc.new_tx(receiver=self.rpc.rand_addr(), priv_key=acct1.key, nonce=1, gas_price=gas_price_level_1), # expected to be ignored and can be resend later
            self.rpc.new_tx(receiver=self.rpc.rand_addr(), priv_key=acct1.key, nonce=2, gas_price=gas_price_level_2) # expected to be ignored
        ]
        
        acct2_txs = [
            self.rpc.new_tx(receiver=self.rpc.rand_addr(), priv_key=acct2.key, nonce=0, gas_price=gas_price_level_2), # expected to succeed
            self.rpc.new_tx(receiver=self.rpc.rand_addr(), priv_key=acct2.key, nonce=1, gas_price=gas_price_level_2), # expected to succeed
            self.rpc.new_tx(receiver=self.rpc.rand_addr(), priv_key=acct2.key, nonce=2, gas_price=gas_price_level_2) # expected to succeed
        ]
        
        block_b, block_f = self.construct_non_pivot_block(
            CfxAccount.from_key(default_config["GENESIS_PRI_KEY"]), [*acct1_txs, *acct2_txs], starting_block_hash=block_p, epoch_delta=5
        )

        assert gas_price_level_2 > self.rpc.base_fee_per_gas() * BURNT_RATIO
        assert gas_price_level_1 < self.rpc.base_fee_per_gas() * BURNT_RATIO, f"gas_price_level_1 {gas_price_level_1} should be less than {self.rpc.base_fee_per_gas() * BURNT_RATIO}"

        # wait for epoch of block f executed
        parent_block = block_f
        for _ in range(30):
            block = self.rpc.generate_custom_block(parent_hash = parent_block, referee = [], txs = [])
            parent_block = block

        assert_equal(self.rpc.get_nonce(acct1.address), 1)
        assert_equal(self.rpc.get_nonce(acct2.address), 3)
        focusing_block = self.rpc.block_by_hash(block_b, True)
        assert_equal(focusing_block["transactions"][0]["status"] ,"0x0")
        assert_equal(focusing_block["transactions"][1]["status"] , None)
        assert_equal(focusing_block["transactions"][1]["blockHash"] , None)
        assert_equal(focusing_block["transactions"][2]["status"] , None)
        assert_equal(focusing_block["transactions"][2]["blockHash"] , None)
        
        # as comparison
        assert_equal(focusing_block["transactions"][3]["status"] , "0x0")
        assert_equal(focusing_block["transactions"][4]["status"] , "0x0")
        assert_equal(focusing_block["transactions"][5]["status"] , "0x0")

        self.rpc.generate_blocks(20, 5)
        
        # transactions shall be sent back to txpool and then get packed
        assert_equal(self.rpc.get_nonce(acct1.address), 3)


if __name__ == "__main__":
    CIP137Test().main()
