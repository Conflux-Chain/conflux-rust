import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_greater_than

class TestGasPrice(RpcClient):
    # FIXME remove the "_" prefix to enable this test case
    # once default gas price defined.
    def _test_default_value(self):
        price = self.gas_price()
        assert_greater_than(price, 0)

    def test_nochange_without_tx(self):
        price = self.gas_price()
        self.generate_block()
        price2 = self.gas_price()
        assert_equal(price, price2)

    def test_median_prices(self):
        sender = self.GENESIS_ADDR

        prices = [7,5,1,9,3]
        txs = []
        n = self.get_nonce(sender)

        # generate 100 blocks to make sure the gas price is only decided by below txs.
        self.generate_blocks(100)

        # sent txs
        for p in prices:
            tx = self.new_tx(nonce=n, gas_price=p)
            tx_hash = self.send_tx(tx)
            txs.append(tx_hash)
            n += 1

        self.generate_blocks_to_state(10, len(txs))

        # wait for receipts of sent txs
        for tx in txs:
            self.wait_for_receipt(tx, 1, 10, False)

        # median of prices
        assert_equal(self.gas_price(), 1)

