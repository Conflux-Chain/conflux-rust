#!/usr/bin/env python3
import rlp
from eth_utils import decode_hex
from rlp.sedes import CountableList

from conflux import utils, trie
from conflux.config import DEFAULT_PY_TEST_CHAIN_ID, default_config
from conflux.messages import BlockHeader, Block, Transactions, Account
from conflux.transactions import Transaction, UnsignedTransaction
from conflux.utils import *
from trie import HexaryTrie
import time
import jsonrpcclient

TEST_DIFFICULTY = 4
HASH_MAX = 1 << 256


def create_block(parent_hash=default_config["GENESIS_PREVHASH"], height=0, timestamp=None, difficulty=TEST_DIFFICULTY, transactions=[],
                 gas_limit=default_config["GENESIS_GAS_LIMIT"], referee_hashes=[], author=default_config["GENESIS_COINBASE"],
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
        gas_limit=default_config["GENESIS_GAS_LIMIT"],
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
                       data=b'', pri_key=default_config["GENESIS_PRI_KEY"], storage_limit=0, epoch_height = 0, chain_id = DEFAULT_PY_TEST_CHAIN_ID, node=None):
    transaction = UnsignedTransaction(nonce, gas_price, gas, receiver, value, data, storage_limit, epoch_height, chain_id)
    return transaction.sign(pri_key)


def wait_for_initial_nonce_for_privkey(node, key, timeout=10):
    key = normalize_key(key)
    addr = priv_to_addr(key)
    return wait_for_initial_nonce_for_address(node, addr, timeout)


def wait_for_initial_nonce_for_address(node, addr, timeout=10):
    return 0
    addr = encode_hex_0x(addr)
    if addr == encode_hex_0x(priv_to_addr(default_config["GENESIS_PRI_KEY"])).lower():
        return 0
    nonce = 0
    start = time.time()
    last_exception = None
    while nonce == 0:
        if time.time() - start > timeout:
            raise AssertionError("Wait for initial nonce for address {} timeout after {} seconds, last exception is {}"
                                 .format(addr, timeout, last_exception))
        try:
            nonce = int(node.cfx_getNextNonce(addr), 0)
        except jsonrpcclient.exceptions.ReceivedErrorResponseError as e:
            # It's possible that
            last_exception = e
            pass
    return nonce


# Wait until that all accounts have stable start nonce.
# FIXME: 10 seconds is just an empirical value. We need confirmation for this.
def wait_for_account_stable():
    time.sleep(10)


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
