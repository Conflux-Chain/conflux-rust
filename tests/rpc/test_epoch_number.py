import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestEpochNumber(RpcClient):
    def test_num_default(self):
        epoch = self.epoch_number()
        
        # 1 new blocks
        self.generate_block()
        epoch2 = self.epoch_number()
        assert_equal(epoch + 1, epoch2)

        # N new blocks
        self.generate_blocks(3)
        epoch3 = self.epoch_number()
        assert_equal(epoch2 + 3, epoch3)

    def test_num_valid(self):
        num = self.epoch_number(self.EPOCH_LATEST_MINED)
        self.epoch_number(self.EPOCH_LATEST_STATE)

        assert_equal(self.epoch_number(self.EPOCH_EARLIEST), 0)
        assert_equal(self.epoch_number(self.EPOCH_NUM(num)), num)
        assert_equal(self.epoch_number(self.EPOCH_NUM(num // 2)), num // 2)

    def test_num_invalid(self):
        assert_raises_rpc_error(None, None, self.epoch_number, "")
        assert_raises_rpc_error(None, None, self.epoch_number, "dummy_num")
        assert_raises_rpc_error(None, None, self.epoch_number, self.EPOCH_LATEST_MINED.upper())
        assert_raises_rpc_error(None, None, self.epoch_number, "Latest_mined")
        assert_raises_rpc_error(None, None, self.epoch_number, "6")
        assert_raises_rpc_error(None, None, self.epoch_number, "0X5")
        assert_raises_rpc_error(None, None, self.epoch_number, "0xg")

        num = self.epoch_number(self.EPOCH_LATEST_MINED)
        assert_raises_rpc_error(None, None, self.epoch_number, self.EPOCH_NUM(num + 1))

    def test_pivot_chain_changed(self):
        root = self.generate_block()

        self.generate_blocks(3)
        epoch = self.epoch_number(self.EPOCH_LATEST_MINED)

        f1 = self.generate_block_with_parent(root, [])
        # add 3 children for f1 so that f1 become the pivot chain
        for _ in range(0, 3):
            self.generate_block_with_parent(f1, [])

        new_epoch = self.epoch_number(self.EPOCH_LATEST_MINED)
        assert_equal(new_epoch, epoch - 1)