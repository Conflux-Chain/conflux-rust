import sys
import time
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import *

class TestGetBlockRewardInfo(RpcClient):
    def test_two_chains(self):
        root = self.generate_block()

        f1 = self.generate_block_with_parent(root, [])
        f2 = self.generate_block_with_parent(root, [])
        f_pivot = max(f1, f2)
        f_ref = min(f1, f2)
        b = self.generate_block()
        for i in range(0, 10):
            self.generate_block()
        time.sleep(1)

        epoch = self.epoch_number(self.EPOCH_LATEST_MINED)
        assert_raises_rpc_error(-32602,
            "Invalid parameters: epoch",
            self.get_block_reward_info, self.EPOCH_LATEST_MINED)
        assert_raises_rpc_error(-32602,
            "Invalid parameters: epoch",
            self.get_block_reward_info, self.EPOCH_NUM(epoch - 10))

        for i in range(0, 7):
            self.generate_block()
        time.sleep(1)

        # After 12 (REWARD_EPOCH_COUNT) + 5 (DEFERRED_STATE_COUNT) epochs, rewards should always be available
        res = self.get_block_reward_info(self.EPOCH_NUM(epoch - 10))
        print(res)
        assert(len(res) == 2)
        for reward_info in res:
            if reward_info['blockHash'] == b:
                assert_equal(reward_info['baseReward'], '0x6124fee993bc0000')
                assert_equal(reward_info['totalReward'], '0x6124fee9a1e91442')
                assert_equal(reward_info['txFee'], '0x0')
            else:
                assert_equal(reward_info['baseReward'], '0x6122824420644000')
                assert_equal(reward_info['totalReward'], '0x612282442e90f75b')
                assert_equal(reward_info['txFee'], '0x0')
