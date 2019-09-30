import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error

class TestGetNonce(RpcClient):
    def test_account_not_found(self):
        addr = self.rand_addr()
        nonce = self.get_nonce(addr)
        assert_equal(nonce, 0)

    def test_account_exists(self):
        addr = self.GENESIS_ADDR
        nonce = self.get_nonce(addr)

        tx = self.new_tx()
        self.send_tx(tx, True)

        nonce2 = self.get_nonce(addr)
        assert_equal(nonce2, nonce + 1)

    def test_epoch_earliest(self):
        addr = self.GENESIS_ADDR
        nonce = self.get_nonce(addr, self.EPOCH_EARLIEST)
        assert_equal(nonce, 0)

    def test_epoch_latest_state(self):
        nonce1 = self.get_nonce(self.GENESIS_ADDR)
        nonce2 = self.get_nonce(self.GENESIS_ADDR, self.EPOCH_LATEST_STATE)
        assert_equal(nonce1, nonce2)
        

    def test_epoch_latest_mined(self):
        assert_raises_rpc_error(None, None, self.get_nonce, self.GENESIS_ADDR, self.EPOCH_LATEST_MINED)

    def test_epoch_num_0(self):
        addr = self.GENESIS_ADDR
        nonce = self.get_nonce(addr, "0x0")
        assert_equal(nonce, 0)

    def test_epoch_num_too_large(self):
        mined_epoch = self.epoch_number()
        assert_raises_rpc_error(None, None, self.get_nonce, self.GENESIS_ADDR, self.EPOCH_NUM(mined_epoch + 1))

        stated_epoch = self.epoch_number(self.EPOCH_LATEST_STATE)
        for num in range(stated_epoch + 1, mined_epoch):
            assert_raises_rpc_error(None, None, self.get_nonce, self.GENESIS_ADDR, self.EPOCH_NUM(num))

    def test_epoch_num(self):
        addr = self.GENESIS_ADDR

        pre_epoch = self.epoch_number()
        pre_nonce = self.get_nonce(addr)

        # send tx to change the nonce
        tx = self.new_tx(nonce=pre_nonce)
        self.send_tx(tx, True)

        new_nonce = self.get_nonce(addr, self.EPOCH_NUM(pre_epoch))
        assert_equal(new_nonce, pre_nonce)

    def test_block_hash(self):
        addr = self.GENESIS_ADDR
        pre_nonce = self.get_nonce(addr)
        tx = self.new_tx(nonce=pre_nonce)
        tx_hash = self.send_tx(tx, True)
        block_hash = self.get_receipt(tx_hash)["blockHash"]
        new_nonce = self.get_nonce(addr=addr, block_hash=block_hash)
        assert_equal(new_nonce, pre_nonce + 1)
