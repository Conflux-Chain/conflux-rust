import sys

from test_framework.blocktools import create_transaction

sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestTrace(RpcClient):
    def test_trace_after_reorg(self):
        genesis = self.best_block_hash()
        tx = create_transaction()
        b1 = self.generate_custom_block(parent_hash=genesis, referee=[], txs=[tx])
        self.wait_for_receipt(tx.hash_hex())
        trace1 = self.get_block_trace(b1)
        assert_equal(len(trace1["transactionTraces"]), 1)
        assert_equal(len(trace1["transactionTraces"][0]["traces"]), 1)
        chain1_best_epoch = self.epoch_number()

        b2 = self.generate_custom_block(parent_hash=genesis, referee=[], txs=[tx])
        parent = b2
        for _ in range(chain1_best_epoch):
            parent = self.generate_custom_block(parent_hash=parent, referee=[], txs=[])
        self.generate_custom_block(parent_hash=parent, referee=[b1], txs=[])
        self.generate_blocks_to_state()
        chain2_best_epoch = self.epoch_number()

        trace3 = self.get_block_trace(b2)
        assert_equal(len(trace3["transactionTraces"]), 1)
        assert_equal(len(trace3["transactionTraces"][0]["traces"]), 1)
        trace2 = self.get_block_trace(b1)
        assert_equal(len(trace2["transactionTraces"]), 1)
        assert_equal(len(trace2["transactionTraces"][0]["traces"]), 0)
        parent = b1
        for _ in range(chain2_best_epoch):
            parent = self.generate_custom_block(parent_hash=parent, referee=[], txs=[])
        self.generate_custom_block(parent_hash=parent, referee=[b2], txs=[])
        self.generate_blocks_to_state()

        trace4 = self.get_block_trace(b1)
        assert_equal(len(trace4["transactionTraces"]), 1)
        assert_equal(len(trace4["transactionTraces"][0]["traces"]), 1)
        trace5 = self.get_block_trace(b2)
        assert_equal(len(trace5["transactionTraces"]), 1)
        assert_equal(len(trace5["transactionTraces"][0]["traces"]), 0)

    def test_trace_transaction(self):
        tx = self.new_tx()
        tx_hash = self.send_tx(tx)
        self.wait_for_receipt(tx_hash)
        assert_equal(len(self.get_transaction_trace(tx_hash)), 1)
