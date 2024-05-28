from conflux.rpc import RpcClient
from test_framework.util import (
    assert_equal,
)

from cfx_account import Account as CfxAccount

from test_framework.test_framework import ConfluxTestFramework

class CIP137Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

    # We need to ensure that the tx in B block

    #                      ---        ---        ---        ---        ---
    #                  .- | A | <--- | C | <--- | D | <--- | E | <--- | F | <--- ...
    #           ---    |   ---        ---        ---        ---        ---
    # ... <--- | P | <-*                                                .
    #           ---    |   ---                                          .
    #                  .- | B | <........................................
    #                      ---

    # continuously fill transaction in C to F to increase base gas fee for F epoch
    # then transaction in B block will fail
    def run_test(self):
        def base_fee_per_gas(epoch: str = "latest_mined"):
            return self.rpc.fee_history(1, epoch)['base_fee_per_gas'][0]

        acct1 = CfxAccount.create()
        acct2 = CfxAccount.create()
        gas_price_level_1 = 2
        gas_price_level_2 = 10
        burnt_ratio = 0.5
        
        assert base_fee_per_gas() < gas_price_level_1 * burnt_ratio

        # send 1000 CFX to each account
        self.rpc.send_tx(self.rpc.new_tx(receiver=acct1.address, value=10**21,), True)
        self.rpc.send_tx(self.rpc.new_tx(receiver=acct2.address, value=10**21), True)
        block_p = self.rpc.block_by_epoch("latest_mined")["hash"]
        
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
        

        block_b = self.rpc.generate_custom_block(
            parent_hash=block_p, referee=[], txs=[*acct1_txs, *acct2_txs]
        )

        genesis_nonce = self.rpc.get_nonce(self.rpc.GENESIS_ADDR)

        # block a, c, d, e
        block_a = self.rpc.generate_custom_block(
            parent_hash=block_p,
            referee=[],
            txs=[
                self.rpc.new_tx(
                    receiver=self.rpc.rand_addr(),
                    gas=15000000,
                    nonce=(genesis_nonce := genesis_nonce + 1),
                )
                for i in range(4)
            ],
        )
        block_c = self.rpc.generate_custom_block(
            parent_hash=block_a,
            referee=[],
            txs=[
                self.rpc.new_tx(
                    receiver=self.rpc.rand_addr(),
                    gas=15000000,
                    nonce=(genesis_nonce := genesis_nonce + 1),
                )
                for i in range(4)
            ],
        )
        block_d = self.rpc.generate_custom_block(
            parent_hash=block_c,
            referee=[],
            txs=[
                self.rpc.new_tx(
                    receiver=self.rpc.rand_addr(),
                    gas=15000000,
                    nonce=(genesis_nonce := genesis_nonce + 1),
                )
                for i in range(4)
            ],
        )
        block_e = self.rpc.generate_custom_block(
            parent_hash=block_d,
            referee=[],
            txs=[
                self.rpc.new_tx(
                    receiver=self.rpc.rand_addr(),
                    gas=15000000,
                    nonce=(genesis_nonce := genesis_nonce + 1),
                )
                for i in range(4)
            ],
        )
        block_f = self.rpc.generate_custom_block(
            parent_hash=block_e,
            referee=[block_b],
            txs=[
                self.rpc.new_tx(
                    receiver=self.rpc.rand_addr(),
                    gas=15000000,
                    nonce=(genesis_nonce := genesis_nonce + 1),
                )
                for i in range(4)
            ],
        )
        assert gas_price_level_2 > base_fee_per_gas() * burnt_ratio
        assert gas_price_level_1 < base_fee_per_gas() * burnt_ratio

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
