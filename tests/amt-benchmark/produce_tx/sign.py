from conflux.utils import encode_hex, decode_hex, normalize_key, ecsign
from test_framework.blocktools import create_transaction, UnsignedTransaction, Transaction
from multiprocessing import Pool
from transaction import TxParam
from typing import List
from utils import pool


def sign_transaction_param(input: TxParam):
    unsigned_tx = UnsignedTransaction(**input.tx_args)

    rawhash = unsigned_tx.get_rawhash()
    key = normalize_key(input.privkey)

    v, r, s = ecsign(rawhash, key)
    v = v - 27

    return dict(v=v, r=r, s=s)


def make_transaction(input: TxParam, sig) -> Transaction:
    unsigned_tx = UnsignedTransaction(**input.tx_args)
    tx = Transaction(transaction=unsigned_tx, **sig)
    tx._sender = input.sender
    return tx


def _sign_multi_process(transactions, log) -> List[Transaction]:
    # log("Sign")

    with pool() as p:
        sigs = p.map(sign_transaction_param, transactions)

    # log("Organize")

    return [make_transaction(param, sig) for (param, sig) in zip(transactions, sigs)]


def _sign(transactions, log) -> List[Transaction]:
    # log("Sign and Organize")

    return [make_transaction(param, sign_transaction_param(param)) for param in transactions]


def sign(transactions: List[TxParam], **kwargs) -> List[Transaction]:
    log = kwargs.get("log", print)
    if len(transactions) > 60:
        return _sign_multi_process(transactions, log)
    else:
        return _sign(transactions, log)
