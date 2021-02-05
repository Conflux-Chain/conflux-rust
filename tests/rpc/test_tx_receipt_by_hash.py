import eth_utils
import sys, os
sys.path.append("..")

from conflux.address import b32_address_to_hex
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak
from test_framework.blocktools import encode_hex_0x
from test_framework.util import assert_equal, assert_ne

CONTRACT_PATH = "../contracts/simple_storage.dat"
NUM_TXS = 10

class TestGetTxReceiptByHash(RpcClient):
    def test_simple_receipt(self):
        to = self.rand_addr()
        tx = self.new_tx(receiver=to)

        tx_hash = self.send_tx(tx, wait_for_receipt=True)
        tx2 = self.get_tx(tx_hash)

        receipt = self.get_transaction_receipt(tx_hash)
        assert_ne(receipt, None)

        assert_equal(receipt['blockHash'], tx2['blockHash'])
        assert_equal(receipt['contractCreated'], tx2['contractCreated'])
        assert_equal(receipt['from'], tx2['from'])
        assert_equal(receipt['index'], tx2['transactionIndex'])
        assert_equal(receipt['to'], tx2['to'])
        assert_equal(receipt['transactionHash'], tx_hash)

        assert_equal(receipt['gasCoveredBySponsor'], False)
        assert_equal(receipt['logs'], [])
        assert_equal(receipt['outcomeStatus'], '0x0')
        assert_equal(receipt['storageCollateralized'], '0x0')
        assert_equal(receipt['storageCoveredBySponsor'], False)
        assert_equal(receipt['storageReleased'], [])
        assert_equal(receipt['txExecErrorMsg'], None)

    def test_receipt_with_storage_changes(self):
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert (os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()

        # deploy contract
        tx = self.new_contract_tx(receiver="", data_hex=bytecode, storage_limit=20000)
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        receipt = self.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt['outcomeStatus'], '0x0')
        contract = receipt['contractCreated']

        assert_equal(receipt['storageCollateralized'], '0x280')
        assert_equal(receipt['storageReleased'], [])

        # call increment()
        data_hex = encode_hex_0x(keccak(b"increment()"))
        tx = self.new_contract_tx(receiver=contract, data_hex=data_hex, storage_limit=20000)
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        receipt = self.get_transaction_receipt(tx.hash_hex())

        assert_equal(receipt['storageCollateralized'], '0x0')
        assert_equal(receipt['storageReleased'], [])

        # call destroy()
        data_hex = encode_hex_0x(keccak(b"destroy()"))
        tx = self.new_contract_tx(receiver=contract, data_hex=data_hex, storage_limit=20000)
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        receipt = self.get_transaction_receipt(tx.hash_hex())

        assert_equal(receipt['storageCollateralized'], '0x0')

        assert_equal(len(receipt['storageReleased']), 1)
        assert_equal(receipt['storageReleased'][0]['collaterals'], '0x280')
        assert_equal(b32_address_to_hex(receipt['storageReleased'][0]['address']), self.GENESIS_ADDR)

    def test_get_block_receipts(self):
        parent_hash = self.block_by_epoch("latest_mined")['hash']
        start_nonce = self.get_nonce(self.GENESIS_ADDR)

        txs = [self.new_tx(receiver=self.rand_addr(), nonce = start_nonce + ii) for ii in range(NUM_TXS)]
        block_hash = self.generate_custom_block(parent_hash = parent_hash, referee = [], txs = txs)
        self.generate_blocks(5)

        receipts = self.node.cfx_getBlockReceipts(block_hash)
        assert_ne(receipts, None)
        assert_equal(len(receipts), NUM_TXS)