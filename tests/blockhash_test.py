from conflux.utils import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *


class BlockHashFromStateTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
    
    def run_test(self):
        genesis_hash = self.client.block_by_epoch(0)["hash"]
        for _ in range(5):
            self.client.generate_block_with_parent(genesis_hash)

        self.wait_for_block(1000)

        test_contract = self.deploy_contract("BlockHash")
        context_contract = self.internal_contract("ConfluxContext")
        for i in range(100, 1001, 100):
            assert_equal(test_contract.functions.getBlockHash(i).call().hex(), self.client.block_by_block_number(i)["hash"][2:])
            assert_equal(context_contract.functions.epochHash(i).call().hex(), self.client.block_by_epoch(i)["hash"][2:])

        self.log.info("Generate 65536+ blocks")
        for i in range(5000, 66000, 5000):
            self.wait_for_block(i)
        self.wait_for_block(66000)

        assert_equal(test_contract.functions.getBlockHash(100).call().hex(), "0" * 64)
        assert_equal(context_contract.functions.epochHash(100).call().hex(), "0" * 64)
        

    def wait_for_block(self, block_number, have_not_reach=False):
        if have_not_reach:
            assert_greater_than_or_equal(
                block_number,  self.client.epoch_number())
        while self.client.epoch_number() < block_number:
            self.client.generate_blocks(
                block_number - self.client.epoch_number())
            time.sleep(0.1)
            self.log.info(f"block_number: {self.client.epoch_number()}")

if __name__ == "__main__":
    BlockHashFromStateTest().main()
