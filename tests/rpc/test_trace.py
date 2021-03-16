import sys

from test_framework.blocktools import create_transaction

sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestTrace(RpcClient):
    def test_trace_after_reorg(self):
        genesis = self.best_block_hash()
        tx = self.new_tx()
        b1 = self.generate_custom_block(parent_hash=genesis, referee=[], txs=[tx])
        self.wait_for_receipt(tx.hash_hex())
        receipt = self.get_transaction_receipt(tx.hash_hex())
        trace1 = self.get_block_trace(b1)
        expected_trace = {
            'blockHash': b1,
            'epochHash': b1,
            'epochNumber': receipt["epochNumber"],
            'transactionTraces': [{
                'traces': [{
                    'action': {
                        'callType': 'call',
                        'from': 'NET10:TYPE.USER:AAR8JZYBZV0FHZREAV49SYXNZUT8S0JT1ASMXX99XH',
                        # FIXME: This should not be 0?
                        'gas': '0x0',
                        'input': '0x',
                        'to': 'NET10:TYPE.USER:AAJBAEAUCAJBAEAUCAJBAEAUCAJBAEAUCA902UEXYP',
                        'value': '0x64'
                    },
                    'type': 'call'
                }],
                'transactionHash': tx.hash_hex(),
                'transactionPosition': '0x0'
            }]
        }
        assert_equal(trace1, expected_trace)
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
        receipt = self.get_transaction_receipt(tx_hash)
        expected_trace = [{
            'type': 'call',
            'action': {
                'callType': 'call',
                'from': 'NET10:TYPE.USER:AAR8JZYBZV0FHZREAV49SYXNZUT8S0JT1ASMXX99XH',
                'gas': '0x0',
                'input': '0x',
                'to': 'NET10:TYPE.USER:AAJBAEAUCAJBAEAUCAJBAEAUCAJBAEAUCA902UEXYP',
                'value': '0x64'
            },
            'blockHash': receipt["blockHash"],
            'epochHash': receipt["blockHash"],
            'epochNumber': receipt["epochNumber"],
            'transactionHash': tx_hash,
            'transactionPosition': '0x0',
        }]
        assert_equal(self.get_transaction_trace(tx_hash), expected_trace)

    def test_filter_trace(self):
        tx = self.new_tx()
        tx_hash = self.send_tx(tx)
        self.wait_for_receipt(tx_hash)
        receipt = self.get_transaction_receipt(tx_hash)
        block_hash = receipt["blockHash"]
        trace = self.filter_trace({"blockHashes": [block_hash]})
        expected_trace = [{
            'action': {
                'callType': 'call',
                'from': 'NET10:TYPE.USER:AAR8JZYBZV0FHZREAV49SYXNZUT8S0JT1ASMXX99XH',
                'gas': '0x0',
                'input': '0x',
                'to': 'NET10:TYPE.USER:AAJBAEAUCAJBAEAUCAJBAEAUCAJBAEAUCA902UEXYP',
                'value': '0x64'
            },
            'blockHash': block_hash,
            'epochHash': block_hash,
            'epochNumber': receipt["epochNumber"],
            'transactionHash': tx_hash,
            'transactionPosition': '0x0',
            'type': 'call'
        }]
        assert_equal(trace, expected_trace)