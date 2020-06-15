import sys
sys.path.append("..")

from conflux.filter import Filter
from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

NULL_H160 = "0x0000000000000000000000000000000000000000"
NULL_H256 = "0x0000000000000000000000000000000000000000000000000000000000000000"

class TestGetLogs(RpcClient):
    def test_invalid_filter(self):
        self.blocks = self.generate_blocks_to_state()

        # invalid epoch type
        filter = Filter(from_epoch=0)
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter(from_epoch="latest") # should be `latest_state` or `latest_mined`
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # inconsistent epoch numbers
        filter = Filter(from_epoch="0x02", to_epoch="0x01")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter(from_epoch="latest_state", to_epoch="earliest")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid epoch hex
        filter = Filter(from_epoch="0xQQQQ")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `block_hashes` type
        filter = Filter(block_hashes="")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter(block_hashes=["0x0"])
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `block_hashes` length
        filter = Filter(block_hashes=[NULL_H256] * 129)
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `address` type
        filter = Filter(address="")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter(address=["0x0"])
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `topics` type
        filter = Filter(topics="")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter(topics=["0x0"])
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid topics length
        filter = Filter(topics=[NULL_H256] * 5)
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `limit` type
        filter = Filter(limit=1)
        assert_raises_rpc_error(None, None, self.get_logs, filter)

    def test_valid_filter(self):
        # epoch fields inclusive
        filter = Filter(from_epoch="0x1", to_epoch="0x1")
        logs = self.get_logs(filter)
        assert_equal(logs, [])

        # variadic `address` field
        filter = Filter(address=None)
        logs = self.get_logs(filter)
        assert_equal(logs, [])

        filter = Filter(address=NULL_H160)
        logs = self.get_logs(filter)
        assert_equal(logs, [])

        filter = Filter(address=[NULL_H160, NULL_H160])
        logs = self.get_logs(filter)
        assert_equal(logs, [])

        # variadic `topics` field
        filter = Filter(topics=None)
        logs = self.get_logs(filter)
        assert_equal(logs, [])

        filter = Filter(topics=[NULL_H256])
        logs = self.get_logs(filter)
        assert_equal(logs, [])

        filter = Filter(topics=[NULL_H256, [NULL_H256]])
        logs = self.get_logs(filter)
        assert_equal(logs, [])

        # non-existent block hash
        filter = Filter(block_hashes=[NULL_H256])
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # all fields
        filter = Filter(
            from_epoch="0x0",
            to_epoch="latest_state",
            block_hashes = [self.blocks[0]],
            address=[NULL_H160],
            topics=[NULL_H256, [NULL_H256, NULL_H256]],
            limit="0x1"
        )
        logs = self.get_logs(filter)
        assert_equal(logs, [])