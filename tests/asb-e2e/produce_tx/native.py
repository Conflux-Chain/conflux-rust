import random
from typing import List

from .account import get_account
from .transaction import TxParam



def _transfer_sequential(from_list, to_list):
    from_list = list(from_list)
    return [(random.choice(from_list), i) for i in to_list]


def _transfer_random(from_list, to_list, tx_num):
    from_list = list(from_list)
    to_list = list(to_list)
    return [(random.choice(from_list), random.choice(to_list)) for _ in range(tx_num)]


def construct_tx_param(task, value):
    (from_index, to_index) = task
    action = get_account(to_index).address
    return TxParam(from_index, action, value=value)

def faucet_balance(to_index, value, decimals = 18) -> TxParam:
    tx_param = construct_tx_param(("genesis", to_index), int(value * (10 ** decimals)))
    tx_param.assign_nonce()
    return tx_param


def make_transactions(from_list, to_list, value, tx_num=None) -> List[TxParam]:
    if tx_num is None:
        tasks = _transfer_sequential(from_list, to_list)
    else:
        tasks = _transfer_random(from_list, to_list, tx_num)

    return [construct_tx_param(task, value) for task in tasks]
