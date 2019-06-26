import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestGetBlockByHash(RpcClient):
    def test_invalid_params(self):
        # empty hash
        assert_raises_rpc_error(None, None, self.block_by_hash, "", False)
        assert_raises_rpc_error(None, None, self.block_by_hash, "0x", True)
        
        # invalid hash
        assert_raises_rpc_error(None, None, self.block_by_hash, "0x123", False) # too short
        assert_raises_rpc_error(None, None, self.block_by_hash, self.rand_hash() + "123", True) # too long
        assert_raises_rpc_error(None, None, self.block_by_hash, self.rand_hash()[0:-1] + "G", False) # invalid char
        assert_raises_rpc_error(None, None, self.block_by_hash, self.rand_hash()[2:], True) # without 0x prefix

    def test_block_not_found(self):
        dummy_hash = self.rand_hash()
        block = self.block_by_hash(dummy_hash)
        assert_equal(block, None)

    def test_valid_block(self):
        block_hash = self.generate_block()
        
        block1 = self.block_by_hash(block_hash)
        assert_equal(block1["hash"], block_hash)

        block2 = self.block_by_hash(block_hash, True)
        assert_equal(block2["hash"], block_hash)

    def test_block_with_txs(self):
        # send tx
        tx = self.new_tx()
        tx_hash = self.send_tx(tx)

        # generate a block to pack the sent tx,
        # and wait util the tx receipt generated.
        mined_block = self.generate_block(1)
        self.wait_for_receipt(tx_hash)

        # check the mined block with tx hash
        block = self.block_by_hash(mined_block)
        txs = block["transactions"]
        assert_equal(len(txs), 1)
        assert_equal(txs[0], tx_hash)

        # check the mined block with tx content
        block = self.block_by_hash(mined_block, True)
        txs = block["transactions"]
        assert_equal(len(txs), 1)
        assert_equal(txs[0]["hash"], tx_hash)

    def test_pivot_chain_changed(self):
        root = self.generate_block()
        block_hash = self.generate_block()

        # pivot chain changed
        f1 = self.generate_block_with_parent(root, [])
        f2 = self.generate_block_with_parent(f1, [])
        assert_equal(self.best_block_hash(), f2)

        # get block by hash from non-pivot chain
        assert_equal(self.block_by_hash(block_hash)["hash"], block_hash)