import sys
from os.path import join, dirname, realpath

sys.path.insert(1, join(dirname(realpath(__file__)), "../.."))

from test_framework.blocktools import DEFAULT_PY_TEST_CHAIN_ID
from test_framework.mininode import Transactions
from test_framework.blocktools import create_transaction, UnsignedTransaction, Transaction
from conflux.utils import priv_to_addr, normalize_key, ecsign