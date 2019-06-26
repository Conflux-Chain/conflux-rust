import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestGetBlockByEpoch(RpcClient):
    def test_last_mined(self):
        block_hash = self.generate_block()
        block = self.block_by_epoch(self.EPOCH_LATEST_MINED)
        assert_equal(block["hash"], block_hash)

    def test_earliest(self):
        block = self.block_by_epoch(self.EPOCH_EARLIEST)
        assert_equal(int(block["epochNumber"], 0), 0)

    def test_epoch_num(self):
        block_hash = self.generate_block()
        block = self.block_by_hash(block_hash)
        epoch_num = block["epochNumber"]

        block = self.block_by_epoch(epoch_num)
        assert_equal(block["hash"], block_hash)

    def test_epoch_not_found(self):
        block_hash = self.generate_block()
        block = self.block_by_hash(block_hash)
        epoch_num = block["epochNumber"]

        large_epoch = int(epoch_num, 0) + 1
        assert_raises_rpc_error(None, None, self.block_by_epoch, self.EPOCH_NUM(large_epoch), False)

    def test_pivot_chain_changed(self):
        root = self.generate_block()

        blocks = self.generate_blocks_to_state()
        assert_equal(self.block_by_epoch(self.EPOCH_LATEST_MINED)["hash"], blocks[-1])
        assert_equal(self.block_by_epoch(self.EPOCH_LATEST_STATE)["hash"], blocks[-5])
        assert_equal(self.block_by_epoch(self.EPOCH_EARLIEST)["epochNumber"], hex(0))

        parents = [root]
        for _ in blocks[0:-1]:
            parents.append(self.generate_block_with_parent(parents[-1], []))
            # pivot chain not changed
            assert_equal(self.block_by_epoch(self.EPOCH_LATEST_MINED)["hash"], blocks[-1])
            assert_equal(self.block_by_epoch(self.EPOCH_LATEST_STATE)["hash"], blocks[0])
            assert_equal(self.block_by_epoch(self.EPOCH_EARLIEST)["epochNumber"], hex(0))

        # pivot chain may changed (depend on block hash)
        parents.append(self.generate_block_with_parent(parents[-1], []))

        # pivot chain changed
        parents.append(self.generate_block_with_parent(parents[-1], []))
        assert_equal(self.block_by_epoch(self.EPOCH_LATEST_MINED)["hash"], parents[-1])
        assert_equal(self.block_by_epoch(self.EPOCH_LATEST_STATE)["hash"], parents[-5])
        assert_equal(self.block_by_epoch(self.EPOCH_EARLIEST)["epochNumber"], hex(0))