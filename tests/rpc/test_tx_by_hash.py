import eth_utils
import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal

class TestGetTxByHash(RpcClient):
    def test_hash_zero(self):
        tx = self.get_tx(self.ZERO_HASH)
        assert_equal(tx, None)
    
    def test_tx_not_found(self):
        tx_hash = self.rand_hash()
        tx = self.get_tx(tx_hash)
        assert_equal(tx, None)

    def test_tx_pending(self):
        tx = self.new_tx()
        tx_hash = self.send_tx(tx)
        
        tx2 = self.get_tx(tx_hash)
        assert_equal(tx2["hash"], tx_hash)
        assert_equal(tx2["blockHash"], None)
        assert_equal(tx2["transactionIndex"], None)

        self.wait_for_receipt(tx_hash)

    def test_tx_mined(self):
        tx = self.new_tx()
        tx_hash = self.send_tx(tx)
        self.generate_block(1)

        # FIXME should return the tx info when mined.
        # tx2 = self.get_tx(tx_hash)
        # assert_equal(tx2["hash"], tx_hash)
        # assert_equal(tx2["blockHash"], None)
        # assert_equal(tx2["transactionIndex"], None)

        self.wait_for_receipt(tx_hash)

    def test_tx_stated(self):
        to = self.rand_addr()
        tx = self.new_tx(receiver=to)
        tx_hash = self.send_tx(tx, True)

        tx2 = self.get_tx(tx_hash)
        assert_equal(tx2["from"], self.GENESIS_ADDR)
        assert_equal(tx2["to"], to)
        assert_equal(tx2["nonce"], hex(tx.nonce))
        assert_equal(tx2["gas"], hex(tx.gas))
        assert_equal(tx2["gasPrice"], hex(tx.gas_price))
        assert_equal(tx2["value"], hex(tx.value))
        assert_equal(tx2["data"], eth_utils.encode_hex(tx.data))
        assert_equal(tx2["hash"], tx_hash)
        assert_equal(tx2["r"], hex(tx.r))
        assert_equal(tx2["s"], hex(tx.s))
        assert_equal(tx2["v"], hex(tx.v))
        assert_equal(tx2["transactionIndex"], hex(0))

        block = self.block_by_hash(tx2["blockHash"])
        assert_equal(block["transactions"][0], tx_hash)

    def test_pivot_chain_changed(self):
        root = self.generate_block()
        root_epoch = self.epoch_number()

        # create a tx in current pivot chain
        tx = self.new_tx()
        tx_hash = self.send_tx(tx)
        b1 = self.generate_block(1)
        self.wait_for_receipt(tx_hash)
        assert_equal(self.get_tx(tx_hash)["blockHash"], b1)
        epoch_delta = self.epoch_number() - root_epoch

        # new pivot chain
        fork1 = self.generate_block_with_parent(root, [])
        for _ in range(0, epoch_delta*2):
            fork1 = self.generate_block_with_parent(fork1, [])
        assert_equal(self.best_block_hash(), fork1)
        # tx not found in new pivot chain without reference block
        # FIXME currently, the tx/receipt will not be removed in old chain
        # assert_equal(self.get_tx(tx_hash), None)

        # tx found in referenced block
        self.wait_for_receipt(tx_hash)
        assert_equal(self.get_tx(tx_hash)["blockHash"], b1)