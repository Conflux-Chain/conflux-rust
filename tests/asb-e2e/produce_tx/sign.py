from typing import List

from .framework import UnsignedTransaction, Transaction, normalize_key, ecsign
from .transaction import TxParam
from .utils import pool
from . import log


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
    if input.tag is not None:
        log.notice(f"Make transaction for '{input.tag}'. {tx.hash_hex()}")
    return tx


def _sign_multi_process(transactions: List[TxParam]) -> List[Transaction]:
    log.debug("Sign")

    with pool() as p:
        sigs = p.map(sign_transaction_param, transactions)

    log.debug("Organize")

    return [make_transaction(param, sig) for (param, sig) in zip(transactions, sigs)]


def _sign(transactions: List[TxParam]) -> List[Transaction]:
    log.debug("Sign and Organize")

    return [make_transaction(param, sign_transaction_param(param)) for param in transactions]


def sign(transactions: List[TxParam]) -> List[Transaction]:
    if len(transactions) > 60:
        return _sign_multi_process(transactions)
    else:
        return _sign(transactions)
