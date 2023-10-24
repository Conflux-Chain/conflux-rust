from __future__ import annotations

from web3 import Web3
from typing import Dict, Literal, Union, Any
from copy import deepcopy

from .framework import priv_to_addr
from .utils import pool
from . import log

class Account:
    def __init__(self, index: AccountIndex):
        self.index = index
        if index == "genesis":
            self.privkey = bytes.fromhex("46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f")
        else:
            self.privkey = (index + 1).to_bytes(32, "big")
        self.address = priv_to_addr(self.privkey)
        self.hex_checksum = Web3.toChecksumAddress(self.address.hex())
        self.nonce = 0

    def get_and_inc_nonce(self):
        nonce = self.nonce
        self.nonce += 1
        return nonce

AccountIndex = Union[int, Literal["genesis"]]
map: Dict[AccountIndex, Account] = {}
_backup: Dict[Any, Dict[AccountIndex, Account]] = {}

def get_account(index: AccountIndex):
    global map
    return map[index]

def get_account_address(index: AccountIndex):
    global map
    return map[index].address

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
    map["genesis"] = Account("genesis")

def record_account_map(tag):
    log.warn(f"Record accounts at tag '{tag}'")
    global map, _backup
    _backup[tag] = deepcopy(map)

def recover_account_map(tag):
    log.warn(f"Recover accounts from tag '{tag}'")
    global map, _backup
    map = deepcopy(_backup[tag])

def reset_account_map():
    log.warn("Reset accounts")

    global map
    for key in map:
        map[key].nonce = 0


def clear_account_map():
    log.warn("Clear accounts")

    global map
    map = {}

def debug():
    global map
    for index, account in map.items():
        log.critical(index, account.address.hex())