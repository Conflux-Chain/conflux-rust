#!/usr/bin/env python3
import rlp
from eth_utils import decode_hex
from rlp.sedes import CountableList

from conflux import utils, trie
from conflux.config import default_config
from conflux.messages import BlockHeader, Block, Transactions, Account
from conflux.transactions import Transaction, UnsignedTransaction
from conflux.utils import *
from trie import HexaryTrie
import time

TEST_DIFFICULTY = 4
HASH_MAX = 1 << 256


def create_block(parent_hash=default_config["GENESIS_PREVHASH"], height=0, timestamp=None, difficulty=TEST_DIFFICULTY, transactions=[],
                 gas_limit=3000000000, referee_hashes=[], author=default_config["GENESIS_COINBASE"],
                 deferred_state_root=default_config["GENESIS_STATE_ROOT"], deferred_receipts_root=default_config["GENESIS_RECEIPTS_ROOT"],
                 deferred_logs_bloom_hash=default_config["GENESIS_LOGS_BLOOM_HASH"], adaptive=0):
    if timestamp is None:
        timestamp = int(time.time())
    tx_root = utils.sha3(rlp.encode(Transactions(transactions)))
    nonce = 0
    while True:
        header = BlockHeader(parent_hash=parent_hash, height=height, difficulty=difficulty, timestamp=timestamp,
                             author=author, transactions_root=tx_root, gas_limit=gas_limit,
                             referee_hashes=referee_hashes, nonce=nonce, deferred_state_root=deferred_state_root,
                             deferred_receipts_root=deferred_receipts_root, deferred_logs_bloom_hash=deferred_logs_bloom_hash, adaptive=adaptive)
        if header.pow_decimal() * difficulty < HASH_MAX:
            break
        nonce += 1
    block = Block(block_header=header, transactions=transactions)
    return block


def create_block_with_nonce(
        parent_hash=default_config["GENESIS_PREVHASH"],
        height=0,
        timestamp=None,
        difficulty=TEST_DIFFICULTY,
        transactions=[],
        gas_limit=3000000000,
        referee_hashes=[],
        author=default_config["GENESIS_COINBASE"],
        deferred_state_root=default_config["GENESIS_STATE_ROOT"],
        deferred_receipts_root=default_config["GENESIS_RECEIPTS_ROOT"],
        deferred_logs_bloom_hash=default_config["GENESIS_LOGS_BLOOM_HASH"],
        adaptive=0,
        nonce=0):
    if timestamp is None:
        timestamp = int(time.time())
    tx_root = utils.sha3(rlp.encode(Transactions(transactions)))
    header = BlockHeader(
        parent_hash=parent_hash,
        height=height,
        difficulty=difficulty,
        timestamp=timestamp,
        author=author,
        transactions_root=tx_root,
        gas_limit=gas_limit,
        referee_hashes=referee_hashes,
        nonce=nonce,
        deferred_state_root=deferred_state_root,
        deferred_receipts_root=deferred_receipts_root,
        deferred_logs_bloom_hash=deferred_logs_bloom_hash,
        adaptive=adaptive)
    block = Block(block_header=header, transactions=transactions)
    return block


def create_transaction(nonce=0, gas_price=1, gas=21000, value=0, receiver=default_config['GENESIS_COINBASE'],
                       data=b'', pri_key=default_config["GENESIS_PRI_KEY"], storage_limit=2 ** 256 - 1):
    transaction = UnsignedTransaction(nonce, gas_price, gas, receiver, value, data, storage_limit)
    return transaction.sign(pri_key)


def make_genesis():
#     txs = []
#     for i in range(num_txs):
#         sp = decode_hex("46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f")
#         addr = privtoaddr(sp)
#         tx = create_transaction(0, 10**15, 200, 10**9, addr)
#         signed_tx = tx.sign(sp)
#         txs.append(signed_tx)
#     sp = default_config["GENESIS_PRI_KEY"]
#     addr = privtoaddr(sp)
#     state_trie = HexaryTrie(db={})
#     state_trie[addr] = rlp.encode(Account(balance=10**9, nonce=0, storage_root=b'\x00' * 32, code_hash=trie.BLANK_ROOT))
    genesis = create_block(difficulty=0, author=default_config["GENESIS_AUTHOR"], timestamp=0)
    return genesis
