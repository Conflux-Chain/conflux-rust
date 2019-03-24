import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestGetBlocksByEpoch(RpcClient):
    def test_single_chain(self):
        self.generate_block()
        self.generate_blocks_to_state()
        
        # earliest, stated, mined
        self.assert_blocks_in_epoch(self.EPOCH_EARLIEST, 1)
        self.assert_blocks_in_epoch(self.EPOCH_LATEST_STATE, 1)
        self.assert_blocks_in_epoch(self.EPOCH_LATEST_MINED, 1)

        # valid epoch number
        valid_num = self.epoch_number(self.EPOCH_LATEST_MINED)
        self.assert_blocks_in_epoch(self.EPOCH_NUM(valid_num - 1), 1)
        self.assert_blocks_in_epoch(self.EPOCH_NUM(valid_num // 2), 1)
        self.assert_blocks_in_epoch(self.EPOCH_NUM(valid_num // 3), 1)
        self.assert_blocks_in_epoch(self.EPOCH_NUM(0), 1)

        # invalid epoch number
        assert_raises_rpc_error(None, None, self.block_hashes_by_epoch, self.EPOCH_NUM(valid_num+1))

    def assert_blocks_in_epoch(self, epoch: str, num_blocks: int, block_hashes: list = None):
        blocks = self.block_hashes_by_epoch(epoch)
        assert_equal(len(blocks), num_blocks)

        if block_hashes is not None:
            assert_equal(num_blocks, len(block_hashes))
            for block_hash in blocks:
                assert_equal(block_hash in block_hashes, True)

        for block_hash in blocks:
            block = self.block_by_hash(block_hash)
            if epoch.startswith("0x"):
                assert_equal(block["epochNumber"], epoch)
            else:
                assert_equal(block["epochNumber"], self.EPOCH_NUM(self.epoch_number(epoch)))

    def test_two_chains(self):
        root = self.generate_block()

        f1 = self.generate_block_with_parent(root, [])
        f2 = self.generate_block_with_parent(root, [])
        f_pivot = max(f1, f2)
        f_ref = min(f1, f2)
        b = self.generate_block()

        epoch = self.epoch_number(self.EPOCH_LATEST_MINED)
        self.assert_blocks_in_epoch(self.EPOCH_LATEST_MINED, 2, [b, f_ref])
        self.assert_blocks_in_epoch(self.EPOCH_NUM(epoch), 2, [b, f_ref])
        self.assert_blocks_in_epoch(self.EPOCH_NUM(epoch - 1), 1, [f_pivot])
        

