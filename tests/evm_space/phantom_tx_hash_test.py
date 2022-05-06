#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.utils import sha3 as keccak
from test_framework.blocktools import encode_hex_0x
from test_framework.util import *
from test_framework.mininode import *
from web3 import Web3
from base import Web3Base

CROSS_SPACE_CALL_PATH = "../contracts/CrossSpaceCall"
CROSS_SPACE_CALL_ADDRESS = "0x0888000000000000000000000000000000000006"
EVM_CONTRACT_PATH = "../contracts/CrossSpaceEventTest/CrossSpaceEventTestEVMSide"

def encode_u256(number):
    return ("%x" % number).zfill(64)

def number_to_topic(number):
    return "0x" + encode_u256(number)

def mapped_address(hex_addr):
    return "0x" + keccak(bytes.fromhex(hex_addr.replace("0x", "")))[12:].hex()

class PhantomTransactionHashTest(Web3Base):
    def run_test(self):
        # initialize Conflux account
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')

        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 1 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))

        # deploy EVM space contract
        self.evmContractAddr = self.deploy_evm_space(EVM_CONTRACT_PATH + ".bytecode")
        print(f'EVM contract: {self.evmContractAddr}')

        # import CrossSpaceCall abi
        abi_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CROSS_SPACE_CALL_PATH + ".abi")
        assert(os.path.isfile(abi_file))
        abi = open(abi_file).read()
        self.crossSpaceContract = self.w3.eth.contract(abi=abi)

        # create and charge accounts
        cfx_privkey_1 = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0"
        cfx_address_1 = self.w3.eth.account.privateKeyToAccount(cfx_privkey_1).address
        cfx_address_1 = cfx_address_1[:2] + '1' + cfx_address_1[3:]
        self.cross_space_transfer(mapped_address(cfx_address_1), 1 * 10 ** 18)

        self.rpc.send_tx(self.rpc.new_tx(
            value=1 * 10 ** 18,
            receiver=cfx_address_1,
            nonce=self.rpc.get_nonce(self.cfxAccount),
            gas=1000000,
        ), True)

        cfx_privkey_2 = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde1"
        cfx_address_2 = self.w3.eth.account.privateKeyToAccount(cfx_privkey_2).address
        cfx_address_2 = cfx_address_2[:2] + '1' + cfx_address_2[3:]
        self.cross_space_transfer(mapped_address(cfx_address_2), 1 * 10 ** 18)

        self.rpc.send_tx(self.rpc.new_tx(
            value=1 * 10 ** 18,
            receiver=cfx_address_2,
            nonce=self.rpc.get_nonce(self.cfxAccount),
            gas=1000000,
        ), True)

        # withdraw
        data_hex = self.crossSpaceContract.encodeABI(fn_name="withdrawFromMapped", args=[1])

        tx = self.rpc.new_contract_tx(receiver=CROSS_SPACE_CALL_ADDRESS, data_hex=data_hex, sender=cfx_address_1, priv_key=cfx_privkey_1)
        cfx_tx_hash_1 = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfx_tx_hash_1)
        receipt_1 = self.rpc.get_transaction_receipt(cfx_tx_hash_1)
        assert_equal(receipt_1["outcomeStatus"], "0x0")

        block_1 = self.nodes[0].eth_getBlockByHash(receipt_1["blockHash"], True)
        phantom_txs_1 = block_1["transactions"]
        assert_equal(len(phantom_txs_1), 1)
        phantom_hash_1 = phantom_txs_1[0]["hash"]

        tx = self.rpc.new_contract_tx(receiver=CROSS_SPACE_CALL_ADDRESS, data_hex=data_hex, sender=cfx_address_2, priv_key=cfx_privkey_2)
        cfx_tx_hash_2 = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfx_tx_hash_2)
        receipt_2 = self.rpc.get_transaction_receipt(cfx_tx_hash_2)
        assert_equal(receipt_2["outcomeStatus"], "0x0")

        block_2 = self.nodes[0].eth_getBlockByHash(receipt_2["blockHash"], True)
        phantom_txs_2 = block_2["transactions"]
        assert_equal(len(phantom_txs_2), 1)
        phantom_hash_2 = phantom_txs_2[0]["hash"]

        assert_ne(phantom_hash_1, phantom_hash_2) # <<<

        # call
        call_hex = encode_hex_0x(keccak(b"emitEVM(uint256)"))[:10] + encode_u256(0)
        data_hex = self.crossSpaceContract.encodeABI(fn_name="callEVM", args=[self.evmContractAddr, call_hex])

        tx = self.rpc.new_contract_tx(receiver=CROSS_SPACE_CALL_ADDRESS, data_hex=data_hex, sender=cfx_address_1, priv_key=cfx_privkey_1)
        cfx_tx_hash_1 = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfx_tx_hash_1)
        receipt_1 = self.rpc.get_transaction_receipt(cfx_tx_hash_1)
        assert_equal(receipt_1["outcomeStatus"], "0x0")

        block_1 = self.nodes[0].eth_getBlockByHash(receipt_1["blockHash"], True)
        phantom_txs_1 = block_1["transactions"]
        assert_equal(len(phantom_txs_1), 2)
        phantom_hash_1 = phantom_txs_1[1]["hash"]

        tx = self.rpc.new_contract_tx(receiver=CROSS_SPACE_CALL_ADDRESS, data_hex=data_hex, sender=cfx_address_2, priv_key=cfx_privkey_2)
        cfx_tx_hash_2 = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfx_tx_hash_2)
        receipt_2 = self.rpc.get_transaction_receipt(cfx_tx_hash_2)
        assert_equal(receipt_2["outcomeStatus"], "0x0")

        block_2 = self.nodes[0].eth_getBlockByHash(receipt_2["blockHash"], True)
        phantom_txs_2 = block_2["transactions"]
        assert_equal(len(phantom_txs_2), 2)
        phantom_hash_2 = phantom_txs_2[1]["hash"]

        assert_ne(phantom_hash_1, phantom_hash_2) # <<<

        self.log.info("Pass")

if __name__ == "__main__":
    PhantomTransactionHashTest().main()
