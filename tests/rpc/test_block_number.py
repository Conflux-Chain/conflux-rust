import eth_utils
import sys, os
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal

class TestBlockNumber(RpcClient):
    def test_block_number_in_get_block_queries(self):

        #                      ---        ---        ---
        #                  .- | A | <--- | C | <--- | D | <--- ...
        #           ---    |   ---        ---        ---
        # ... <--- | 0 | <-*                          .
        #           ---    |   ---                    .
        #                  .- | B | <..................
        #                      ---

        #               0 --- A --- C --- B --- D ---
        # block number: x  | x+1 | x+2 | x+3 | x+4 |
        # epoch number: y  | y+1 | y+2 |   y + 3   |

        block_0 = self.block_by_epoch("latest_mined")['hash']
        block_a = self.generate_custom_block(parent_hash = block_0, referee = [], txs = [])
        block_b = self.generate_custom_block(parent_hash = block_0, referee = [], txs = [])
        block_c = self.generate_custom_block(parent_hash = block_a, referee = [], txs = [])
        block_d = self.generate_custom_block(parent_hash = block_c, referee = [block_b], txs = [])

        epoch_0 = int(self.block_by_hash(block_0)['height'], 16)
        block_number_0 = int(self.block_by_hash(block_0)['blockNumber'], 16)

        # check block number in `cfx_getBlockByHash`
        assert_equal(int(self.block_by_hash(block_a)['blockNumber'], 16), block_number_0 + 1)
        assert_equal(int(self.block_by_hash(block_c)['blockNumber'], 16), block_number_0 + 2)
        assert_equal(int(self.block_by_hash(block_b)['blockNumber'], 16), block_number_0 + 3)
        assert_equal(int(self.block_by_hash(block_d)['blockNumber'], 16), block_number_0 + 4)

        # check block number in `cfx_getBlockByEpochNumber`
        epoch_a = hex(epoch_0 + 1)
        assert_equal(int(self.block_by_epoch(epoch_a)['blockNumber'], 16), block_number_0 + 1)

        epoch_c = hex(epoch_0 + 2)
        assert_equal(int(self.block_by_epoch(epoch_c)['blockNumber'], 16), block_number_0 + 2)

        # note that this epoch will reference the pivot block (D)
        epoch_d = hex(epoch_0 + 3)
        assert_equal(int(self.block_by_epoch(epoch_d)['blockNumber'], 16), block_number_0 + 4)
