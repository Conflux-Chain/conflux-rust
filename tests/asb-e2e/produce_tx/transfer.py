import sys
import os

sys.path.insert(1, os.path.dirname(os.path.dirname(sys.path[0])))

from test_framework.util import random
import accounts
from transaction import TxParam
from typing import List


def _transfer_sequential(from_list, to_list):
    from_list = list(from_list)
    return [(random.choice(from_list), i) for i in to_list]


def _transfer_random(from_list, to_list, tx_num):
    from_list = list(from_list)
    to_list = list(to_list)
    return [(random.choice(from_list), random.choice(to_list)) for _ in range(tx_num)]


def construct_tx_param(task, value):
    (from_index, to_index) = task
    action = accounts.map[to_index].address
    return TxParam(from_index, action, value=value)


def make_transactions(from_list, to_list, value, tx_num=None) -> List[TxParam]:
    if tx_num is None:
        tasks = _transfer_sequential(from_list, to_list)
    else:
        tasks = _transfer_random(from_list, to_list, tx_num)

    return [construct_tx_param(task, value) for task in tasks]
