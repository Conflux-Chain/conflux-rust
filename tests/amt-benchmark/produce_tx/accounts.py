import sys
import os

sys.path.insert(1, os.path.dirname(os.path.dirname(sys.path[0])))

from conflux.utils import priv_to_addr, encode_hex, decode_hex, normalize_key, ecsign
from test_framework.blocktools import create_transaction, UnsignedTransaction, DEFAULT_PY_TEST_CHAIN_ID, Transaction
from utils import pool
from web3 import Web3

map = {}


class Account:
    def __init__(self, index):
        self.index = index
        self.privkey = (index + 1).to_bytes(32, "big")
        self.address = priv_to_addr(self.privkey)
        self.hex_checksum = Web3.toChecksumAddress(self.address.hex())
        self.nonce = 0

    def get_and_inc_nonce(self):
        nonce = self.nonce
        self.nonce += 1
        return nonce


def assign_nonce(tx_params):
    for param in tx_params:
        index = param["from_index"]
        param["nonce"] = map[index].nonce
        map[index].nonce += 1
        del param["from_index"]


def build_account_map(index_list, **kwargs):
    log = kwargs.get("log", print)
    log("Build accounts")

    global map
    account_list = list(index_list)

    with pool() as p:
        account_list = p.map(Account, account_list)
    map = {account.index: account for account in account_list}


def reset_account_map(**kwargs):
    log = kwargs.get("log", print)
    log("Reset accounts")

    global map
    for key in map:
        map[key].nonce = 0


def clear_account_map(**kwargs):
    log = kwargs.get("log", print)
    log("Clear accounts")

    global map
    map = {}
