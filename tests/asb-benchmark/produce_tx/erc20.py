import sys
import os

sys.path.insert(1, os.path.dirname(os.path.dirname(sys.path[0])))

from test_framework.util import random
import accounts
from transaction import TxParam
from typing import List

import sha3
from semantic_version import Version
from solcx import compile_files
from web3 import Web3

ALL_OUTPUT_VALUES = ["abi", "asm", "ast", "bin", "bin-runtime", "devdoc", "interface", "opcodes", "userdoc"]
FAKE_TO = "0x" + "0" * 40


class Contract:
    def __init__(self, path, name):
        compiled_sol = compile_files([path], output_values=ALL_OUTPUT_VALUES, optimize=True, optimize_runs=200)
        contract = compiled_sol[path + ':' + name]

        w3 = Web3(Web3.EthereumTesterProvider())
        self.contract = w3.eth.contract(abi=contract['abi'], bytecode=contract['bin'])

    def deploy(self, *args):
        func = getattr(self.contract, "constructor")
        return bytearray.fromhex(func(*args).data_in_transaction[2:])

    def call(self, name, *args):
        func = getattr(self.contract.functions, name)
        return bytearray.fromhex(func(*args).buildTransaction({"to": FAKE_TO})["data"][2:])


CONTRACT_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "contract")
erc20_contract = Contract(os.path.join(CONTRACT_PATH, "erc20.sol"), "FixedSupplyToken")


def _transfer_sequential(from_list, to_list):
    from_list = list(from_list)
    return [(random.choice(from_list), i) for i in to_list]


def _transfer_random(from_list, to_list, tx_num):
    from_list = list(from_list)
    to_list = list(to_list)
    return [(random.choice(from_list), random.choice(to_list)) for _ in range(tx_num)]


def construct_erc_param(task, addr, value):
    (from_index, to_index) = task
    # data = erc20_contract.call("transfer", accounts.map[to_index].hex_checksum, value)
    data = bytearray.fromhex("a9059cbb") + bytearray.fromhex("000000000000000000000000") + accounts.map[to_index].address + value.to_bytes(32, 'big')
    return TxParam(from_index, action=addr, data=data, gas=38_000, storage_limit=128)


def make_contract(from_index):
    data = erc20_contract.deploy()
    return TxParam(from_index, data=data, gas=900_000, storage_limit=2400)


def make_transactions(from_list, to_list, value, contract_addr, tx_num=None) -> List[TxParam]:
    if tx_num is None:
        tasks = _transfer_sequential(from_list, to_list)
    else:
        tasks = _transfer_random(from_list, to_list, tx_num)

    return [construct_erc_param(task, contract_addr, value) for task in tasks]
