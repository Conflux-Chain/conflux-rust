import sys
import time
sys.path.append("..")

from conflux.rpc import RpcClient

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
        res = self.get_block_reward_info(self.EPOCH_LATEST_MINED)
        assert(len(res) == 0)
        res = self.get_block_reward_info(self.EPOCH_NUM(epoch - 10))
        assert(len(res) == 0)

        for i in range(0, 7):
            self.generate_block()
        time.sleep(1)

        # After 12 (REWARD_EPOCH_COUNT) + 5 (DEFERRED_STATE_COUNT) epochs, rewards should always be available
        res = self.get_block_reward_info(self.EPOCH_NUM(epoch - 10))
        print(res)
        assert(len(res) == 2)
        for reward_info in res:
            if reward_info['blockHash'] == b:
                assert(reward_info['baseReward'] == '0x6124fee993bc0000')
                assert(reward_info['totalReward'] == '0x6124fee993bc0000')
                assert(reward_info['txFee'] == '0x0')
            else:
                assert(reward_info['baseReward'] == '0x6122824420644000')
                assert(reward_info['totalReward'] == '0x6122824420644000')
                assert(reward_info['txFee'] == '0x0')
