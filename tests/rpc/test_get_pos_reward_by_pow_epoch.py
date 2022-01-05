import sys
import time

sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestGetPosRewardByPowEpoch(RpcClient):
    def test_epoch_has_reward(self):
        while True:
            time.sleep(2)
            self.generate_empty_blocks(4)
            pos_status = self.node.pos_getStatus()
            current_pos_epoch = int(pos_status['epoch'], 0)
            if current_pos_epoch > 2:
                if self.check_pow_and_pos_reward(current_pos_epoch):
                    break

    def test_epoch_has_no_reward(self):
        epoch = "0x1"
        reward_by_pos_epoch = self.node.pos_getRewardsByEpoch(epoch)
        assert_equal(reward_by_pos_epoch, None)

    def check_pow_and_pos_reward(self, current_pos_epoch):
        reward_by_pos_epoch = self.node.pos_getRewardsByEpoch(hex(current_pos_epoch - 1))
        if reward_by_pos_epoch == None:
            return False

        print("check_pow_and_pos_reward", reward_by_pos_epoch)
        pow_epoch_block = self.node.cfx_getBlockByHash(reward_by_pos_epoch["powEpochHash"], False)
        reward_by_pow_epoch = self.node.cfx_getPoSRewardByEpoch(pow_epoch_block["epochNumber"])

        assert_equal(reward_by_pos_epoch["powEpochHash"], reward_by_pow_epoch["powEpochHash"])
        assert_equal(len(reward_by_pos_epoch["accountRewards"]), len(reward_by_pow_epoch["accountRewards"]))

        # convert accountRewards to map and then check value
        pos_reward_map = {x["powAddress"]: x["reward"] for x in reward_by_pos_epoch["accountRewards"]}
        pow_reward_map = {x["powAddress"]: x["reward"] for x in reward_by_pow_epoch["accountRewards"]}
        for key in pow_reward_map:
            assert_equal(pow_reward_map[key], pos_reward_map[key])

        return True