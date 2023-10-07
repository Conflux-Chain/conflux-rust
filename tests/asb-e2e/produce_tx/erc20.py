import random 
from typing import List

from .account import get_account
from .transaction import TxParam
from .contract import Contract
from .calldata_template import address_ph, CalldataTemplate

def _transfer_sequential(from_list, to_list):
    from_list = list(from_list)
    return [(random.choice(from_list), i) for i in to_list]


def _transfer_random(from_list, to_list, tx_num):
    from_list = list(from_list)
    to_list = list(to_list)
    return [(random.choice(from_list), random.choice(to_list)) for _ in range(tx_num)]


def make_transactions(from_list, to_list, value, contract: Contract, tx_num=None) -> List[TxParam]:
    if tx_num is None:
        tasks = _transfer_sequential(from_list, to_list)
    else:
        tasks = _transfer_random(from_list, to_list, tx_num)

    template = contract.build_template("transfer", address_ph(0), value)
    return [template.build_tx_param(from_index, get_account(to_index).address) for (from_index, to_index) in tasks]
