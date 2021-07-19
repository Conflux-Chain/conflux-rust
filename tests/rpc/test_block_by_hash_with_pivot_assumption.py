import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestGetBlockByHashWithPivotAssumption(RpcClient):
    def test_successful(self):
        hash1 = self.generate_block()
        epoch1 = self.block_by_hash(hash1)["epochNumber"]
        hash2 = self.generate_block()
        epoch2 = self.block_by_hash(hash2)["epochNumber"]

        block = self.block_by_hash_with_pivot_assumption(hash1, hash1, epoch1)
        assert_equal(block["hash"], hash1)

        block = self.block_by_hash_with_pivot_assumption(hash2, hash2, epoch2)
        assert_equal(block["hash"], hash2)

    def test_failing(self):
        hash1 = self.generate_block()
        epoch1 = self.block_by_hash(hash1)["epochNumber"]
        hash2 = self.generate_block()
        epoch2 = self.block_by_hash(hash2)["epochNumber"]

        assert_raises_rpc_error(None, None, self.block_by_hash_with_pivot_assumption, hash1, hash1, epoch2)
        assert_raises_rpc_error(None, None, self.block_by_hash_with_pivot_assumption, hash1, hash2, epoch1)
        assert_raises_rpc_error(None, None, self.block_by_hash_with_pivot_assumption, hash1, hash2, epoch2)
        assert_raises_rpc_error(None, None, self.block_by_hash_with_pivot_assumption, hash2, hash1, epoch1)
        assert_raises_rpc_error(None, None, self.block_by_hash_with_pivot_assumption, hash2, hash1, epoch2)
        assert_raises_rpc_error(None, None, self.block_by_hash_with_pivot_assumption, hash2, hash2, epoch1)