import eth_utils
import rlp
import sys
sys.path.append("..")

from conflux.address import hex_to_b32_address
from conflux.rpc import RpcClient
from test_framework.util import assert_equal, assert_raises_rpc_error, assert_is_hash_string

class TestSendTx(RpcClient):
    def test_encode_invalid_hex(self):
        # empty
        assert_raises_rpc_error(None, None, self.send_raw_tx, "")
        assert_raises_rpc_error(None, None, self.send_raw_tx, "0x")
        # odd length
        assert_raises_rpc_error(None, None, self.send_raw_tx, "0x123")
        # invalid character
        assert_raises_rpc_error(None, None, self.send_raw_tx, "0x123G")

    def test_encode_invalid_rlp(self):
        tx = self.new_tx()
        encoded = eth_utils.encode_hex(rlp.encode(tx))

        assert_raises_rpc_error(None, None, self.send_raw_tx, encoded + "12") # 1 more byte
        assert_raises_rpc_error(None, None, self.send_raw_tx, encoded[0:-2])  # 1 less byte

    def test_address_prefix(self):
        # call builtin address starts with 0x0
        tx = self.new_tx(receiver="0x0000000000000000000000000000000000000002", data=b'\x00' * 32, gas=21128)
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        # non-builtin address starts with 0x0
        tx = self.new_tx(receiver="0x00e45681ac6c53d5a40475f7526bac1fe7590fb8")
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        # call address starts with 0x30
        tx = self.new_tx(receiver="0x30e45681ac6c53d5a40475f7526bac1fe7590fb8")
        encoded = eth_utils.encode_hex(rlp.encode(tx))
        assert_raises_rpc_error(None, None, self.send_raw_tx, encoded)
        # call address starts with 0x10
        tx = self.new_tx(receiver="0x10e45681ac6c53d5a40475f7526bac1fe7590fb8")
        assert_equal(self.send_tx(tx, True), tx.hash_hex())

    def test_signature_empty(self):
        tx = self.new_tx(sign=False)
        assert_raises_rpc_error(None, None, self.send_tx, tx)

    def test_gas_zero(self):
        tx = self.new_tx(gas = 0)
        assert_raises_rpc_error(None, None, self.send_tx, tx)

    def test_gas_intrinsic(self):
        tx = self.new_tx(gas = self.DEFAULT_TX_GAS - 1)
        assert_raises_rpc_error(None, None, self.send_tx, tx)

    def test_gas_too_large(self):
        tx = self.new_tx(gas = 10**9 + 1)
        assert_raises_rpc_error(None, None, self.send_tx, tx)

    def test_price_zero(self):
        tx = self.new_tx(gas_price = 0)
        assert_raises_rpc_error(None, None, self.send_tx, tx)

    # FIXME check the maximum size of tx data
    def test_data_too_large(self):
        pass

    # FIXME check the codes (not empty) when create a contract
    def test_data_create_contract(self):
        pass

    # FIXME return error if account balance is not enough.
    def _test_value_less_than_balance(self):
        balance = self.get_balance(self.GENESIS_ADDR)
        tx = self.new_tx(value=balance)
        assert_equal(self.send_tx(tx), self.ZERO_HASH)

    # FIXME return error if account balance is not enough.
    def _test_value_less_than_cost(self):
        balance = self.get_balance(self.GENESIS_ADDR)

        # value = balance - gas_fee
        tx = self.new_tx(value=balance-self.DEFAULT_TX_FEE+1)
        assert_equal(self.send_tx(tx), self.ZERO_HASH)

    def test_tx_already_executed(self):
        tx = self.new_tx()
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        assert_raises_rpc_error(None, None, self.send_tx, tx)

    def test_tx_already_pended(self):
        tx = self.new_tx()
        assert_equal(self.send_tx(tx), tx.hash_hex())
        assert_raises_rpc_error(None, None, self.send_tx, tx)
        self.wait_for_receipt(tx.hash_hex())

    def test_replace_ready_price_too_low(self):
        self.clear_tx_pool()
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)
        tx = self.new_tx(nonce=cur_nonce, gas_price=10)
        assert_equal(self.send_tx(tx), tx.hash_hex())
        assert_equal(self.txpool_status(), (1, 1))

        # replace with lower gas price
        new_tx = self.new_tx(nonce=cur_nonce, gas_price=7)
        assert_raises_rpc_error(None, None, self.send_tx, new_tx)
        assert_equal(self.txpool_status(), (1, 1))

        # replace with equal gas price
        new_tx = self.new_tx(nonce=cur_nonce, value=999)
        assert_raises_rpc_error(None, None, self.send_tx, new_tx)
        assert_equal(self.txpool_status(), (1, 1))

        self.wait_for_receipt(tx.hash_hex())

    def test_replace_pending_price_too_low(self):
        self.clear_tx_pool()
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)
        tx = self.new_tx(nonce=cur_nonce+1, gas_price=10)
        assert_equal(self.send_tx(tx), tx.hash_hex())
        assert_equal(self.txpool_status(), (1, 0))

        # replace with lower gas price
        new_tx = self.new_tx(nonce=cur_nonce+1, gas_price=7)
        assert_raises_rpc_error(None, None, self.send_tx, new_tx)
        assert_equal(self.txpool_status(), (1, 0))

        # replace with equal gas grice
        new_tx = self.new_tx(nonce=cur_nonce+1, gas_price=10)
        assert_raises_rpc_error(None, None, self.send_tx, new_tx)
        assert_equal(self.txpool_status(), (1, 0))

        # cleanup
        missed_tx = self.new_tx(nonce=cur_nonce)
        self.send_tx(missed_tx, True)
        self.wait_for_receipt(tx.hash_hex())

    def test_replace_ready_price_higher(self):
        self.clear_tx_pool()
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)
        tx = self.new_tx(nonce=cur_nonce, gas_price=10)
        assert_equal(self.send_tx(tx), tx.hash_hex())
        assert_equal(self.txpool_status(), (1, 1))

        # replace with higher gas price
        new_tx = self.new_tx(nonce=cur_nonce, gas_price=13)
        assert_equal(self.send_tx(new_tx), new_tx.hash_hex())
        assert_equal(self.txpool_status(), (1, 1))

        # cannot get the old tx anymore
        assert_equal(self.get_tx(tx.hash_hex()), None)
        
        self.wait_for_receipt(new_tx.hash_hex())

    def test_replace_pending_price_higher(self):
        self.clear_tx_pool()
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)
        tx = self.new_tx(nonce=cur_nonce+1, gas_price=10)
        assert_equal(self.send_tx(tx), tx.hash_hex())
        assert_equal(self.txpool_status(), (1, 0))

        # replace with higher gas price
        new_tx = self.new_tx(nonce=cur_nonce+1, gas_price=13)
        assert_equal(self.send_tx(new_tx), new_tx.hash_hex())
        assert_equal(self.txpool_status(), (1, 0))

        # cannot get the old tx anymore
        assert_equal(self.get_tx(tx.hash_hex()), None)
        
        missed_tx = self.new_tx(nonce=cur_nonce)
        self.send_tx(missed_tx, True)
        self.wait_for_receipt(new_tx.hash_hex())

    def test_nonce_stale(self):
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)
        # random receiver to ensure unique tx hash
        tx = self.new_tx(nonce=cur_nonce - 1, receiver=self.rand_addr())
        assert_raises_rpc_error(None, None, self.send_tx, tx)

    def test_larger_nonce(self):
        # send tx with nonce + 1
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)
        tx = self.new_tx(nonce=cur_nonce+1)
        tx_hash = self.send_tx(tx)
        assert_equal(tx_hash, tx.hash_hex())

        # tx with nonce + 1 should be in pool even after N blocks mined
        self.generate_blocks_to_state()
        assert_equal(self.get_tx(tx_hash)["blockHash"], None)

        # send another tx with nonce and stated with receipt
        tx3 = self.new_tx(nonce=cur_nonce)
        assert_equal(self.send_tx(tx3, True), tx3.hash_hex())

        # tx with nonce + 1 is ok for state
        self.wait_for_receipt(tx_hash)
        assert_is_hash_string(self.get_tx(tx_hash)["blockHash"])

    def test_nonce_promote(self):
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)

        self.clear_tx_pool()

        # enter ready queue since tx.nonce = account.nonce
        tx0 = self.new_tx(nonce=cur_nonce)
        assert_equal(self.send_tx(tx0), tx0.hash_hex())
        assert_equal(self.txpool_status(), (1, 1))

        # enter ready queue since tx0 in ready queue
        tx1 = self.new_tx(nonce=cur_nonce+1)
        assert_equal(self.send_tx(tx1), tx1.hash_hex())
        assert_equal(self.txpool_status(), (2, 1))

        # enter pending queue since tx2 not in ready queue
        tx3 = self.new_tx(nonce=cur_nonce+3)
        assert_equal(self.send_tx(tx3), tx3.hash_hex())
        assert_equal(self.txpool_status(), (3, 1))

        # enter the ready queue since tx1 in ready queue,
        # and also promote the tx3 into ready queue.
        tx2 = self.new_tx(nonce=cur_nonce+2)
        assert_equal(self.send_tx(tx2), tx2.hash_hex())
        assert_equal(self.txpool_status(), (4, 1))

        # generate a block to pack above 4 txs and the txpool is empty.
        self.generate_block(num_txs=4)
        assert_equal(self.txpool_status(), (4, 0))

        self.generate_blocks_to_state()
        for tx in [tx0, tx1, tx2, tx3]:
            assert_equal(self.get_transaction_receipt(tx.hash_hex()) is None, False)


    def test_tx_pending_in_pool(self):
        cur_nonce = self.get_nonce(self.GENESIS_ADDR)
        addr = hex_to_b32_address(self.GENESIS_ADDR)

        self.clear_tx_pool()

        # enter ready queue since tx.nonce = account.nonce
        tx0 = self.new_tx(nonce=cur_nonce)
        assert_equal(self.send_tx(tx0), tx0.hash_hex())

        # enter ready queue since tx0 in ready queue
        tx1 = self.new_tx(nonce=cur_nonce+1)
        assert_equal(self.send_tx(tx1), tx1.hash_hex())

        # enter pending queue since tx2 not in ready queue
        tx3 = self.new_tx(nonce=cur_nonce+3)
        assert_equal(self.send_tx(tx3), tx3.hash_hex())

        pending_info = self.node.cfx_getAccountPendingInfo(addr)
        assert_equal(pending_info["localNonce"], hex(cur_nonce))
        assert_equal(pending_info["pendingCount"], hex(3))
        assert_equal(pending_info["pendingNonce"], hex(cur_nonce))
        assert_equal(pending_info["nextPendingTx"], tx0.hash_hex())


        # generate a block to pack above txs.
        self.generate_blocks_to_state(num_txs=4)

        pending_info = self.node.cfx_getAccountPendingInfo(addr)
        assert_equal(pending_info["localNonce"], hex(cur_nonce+2))
        assert_equal(pending_info["pendingCount"], hex(1))
        assert_equal(pending_info["pendingNonce"], hex(cur_nonce+3))
        assert_equal(pending_info["nextPendingTx"], tx3.hash_hex())

        # enter the ready queue since tx1 in ready queue,
        # and also promote the tx3 into ready queue.
        tx2 = self.new_tx(nonce=cur_nonce+2)
        assert_equal(self.send_tx(tx2), tx2.hash_hex())

        pending_info = self.node.cfx_getAccountPendingInfo(addr)
        assert_equal(pending_info["localNonce"], hex(cur_nonce+2))
        assert_equal(pending_info["pendingCount"], hex(2))
        assert_equal(pending_info["pendingNonce"], hex(cur_nonce+2))
        assert_equal(pending_info["nextPendingTx"], tx2.hash_hex())

        # generate a block to pack above txs.
        self.generate_blocks_to_state(num_txs=4)

        pending_info = self.node.cfx_getAccountPendingInfo(addr)
        assert_equal(pending_info["localNonce"], hex(cur_nonce+4))
        assert_equal(pending_info["pendingCount"], hex(0))
        assert_equal(pending_info["pendingNonce"], hex(0))
        assert_equal(pending_info["nextPendingTx"], "0x0000000000000000000000000000000000000000000000000000000000000000")


        self.generate_blocks_to_state(num_txs=4)
        for tx in [tx0, tx1, tx2, tx3]:
            assert_equal(self.get_transaction_receipt(tx.hash_hex()) is None, False)
