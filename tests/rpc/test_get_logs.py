import sys
sys.path.append("..")

from conflux.filter import Filter
from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestGetLogs(RpcClient):
    def test_invalid_filter(self):
        # missing `fromEpoch`
        filter = Filter("0x0", "0x0"); del filter.fromEpoch
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # missing `toEpoch`
        filter = Filter("0x0", "0x0"); del filter.toEpoch
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid epoch type
        filter = Filter(0, "0x0")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid epoch hex
        filter = Filter("0xQQQQ", "0x0")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `blockHashes` type
        filter = Filter("0x0", "0x0", block_hashes="")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter("0x0", "0x0", block_hashes=["0x0"])
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `address` type
        filter = Filter("0x0", "0x0", address="")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter("0x0", "0x0", address=["0x0"])
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `topics` type
        filter = Filter("0x0", "0x0", topics=None)
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter("0x0", "0x0", topics="")
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        filter = Filter("0x0", "0x0", topics=["0x0"])
        assert_raises_rpc_error(None, None, self.get_logs, filter)

        # invalid `limit` type
        filter = Filter("0x0", "0x0", limit=1)
        assert_raises_rpc_error(None, None, self.get_logs, filter)

    def test_valid_filter(self):
        filter = Filter(
            from_epoch="0x0",
            to_epoch="0x0",
            block_hashes=["0x0000000000000000000000000000000000000000000000000000000000000000"],
            address=["0x0000000000000000000000000000000000000000"],
            topics=[["0x0000000000000000000000000000000000000000000000000000000000000000"]],
            limit="0x1"
        )

        logs = self.get_logs(filter)
        assert_equal(logs, [])