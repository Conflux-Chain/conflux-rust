from __future__ import annotations

from web3 import Web3
from typing import Dict

from .framework import priv_to_addr
from .utils import pool
from . import log

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
    
map: Dict[int, Account] = {}

def get_account(index: int):
    global map
    return map[index]

def assign_nonce(tx_params):
    for param in tx_params:
        index = param["from_index"]
        param["nonce"] = map[index].nonce
        map[index].nonce += 1
        del param["from_index"]


def build_account_map(index_list):
    log.warn("Build accounts")

    global map
    account_list = list(index_list)

    with pool() as p:
        account_list = p.map(Account, account_list)
    map = {account.index: account for account in account_list}


def reset_account_map():
    log.warn("Reset accounts")

    global map
    for key in map:
        map[key].nonce = 0


def clear_account_map():
    log.warn("Clear accounts")

    global map
    map = {}
