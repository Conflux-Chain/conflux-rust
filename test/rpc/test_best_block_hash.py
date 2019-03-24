import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal

class TestGetBestBlockHash(RpcClient):
    def test_single_chain(self):
        block_hash = self.generate_block()
        assert_equal(self.best_block_hash(), block_hash)

    def test_two_chain(self):
        root = self.generate_block()

        # new 2 blocks
        blocks = self.generate_blocks(2)
        assert_equal(len(blocks), 2)
        b1 = blocks[0]
        b2 = blocks[1]
        assert_equal(self.best_block_hash(), b2)

        # new block on another fork, but not the best block
        f1 = self.generate_block_with_parent(root, [])
        assert_equal(self.best_block_hash(), b2)

        # new block on another fork, then bigger hash one is the best block
        f2 = self.generate_block_with_parent(f1, [])
        if f1 > b1:
            assert_equal(self.best_block_hash(), f2)
        else:
            assert_equal(self.best_block_hash(), b2)

        # new block on another fork, become the best block
        f3 = self.generate_block_with_parent(f2, [])
        assert_equal(self.best_block_hash(), f3)

