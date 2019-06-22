import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal

class TestBlockSync(RpcClient):
    # FIXME currently not validated yet
    def test_tx_invalid(self):
        # basic tx validation is requried
        pass

    # FIXME currently not validated yet
    def test_tx_dup(self):
        pass

    def test_txpool_ready_remove(self):
        # add tx into pool
        self.clear_tx_pool()
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)
        tx1 = self.new_tx(nonce=cur_nonce)
        self.send_tx(tx1)
        tx2 = self.new_tx(nonce=cur_nonce + 2)
        self.send_tx(tx2)
        assert_equal(self.txpool_status(), (2, 1))

        # generate a block with above txs
        best_block = self.best_block_hash()
        new_block = self.generate_custom_block(best_block, [], [tx1, tx2])
        assert_equal(self.best_block_hash(), new_block)

        # tx should be removed from pool
        assert_equal(self.txpool_status(), (2, 0))

        # tx1 executed, tx2 put back to pool
        self.generate_blocks_to_state(num_txs=2)
        self.wait_for_receipt(tx1.hash_hex())
        assert_equal(self.txpool_status(), (2, 0))

        # send the missed tx
        tx3 = self.new_tx(nonce=cur_nonce + 1)
        assert_equal(self.send_tx(tx3), tx3.hash_hex())
        self.generate_block(num_txs=2)
        self.generate_blocks_to_state()
        assert_equal(self.txpool_status(), (3, 0))
        self.wait_for_receipt(tx2.hash_hex())
        self.wait_for_receipt(tx3.hash_hex())
