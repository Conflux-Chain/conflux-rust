import pickle
import sys
import os

sys.path.insert(1, os.path.dirname(os.path.dirname(sys.path[0])))

from conflux.utils import priv_to_addr, encode_hex, decode_hex, normalize_key, ecsign
from test_framework.blocktools import create_transaction, UnsignedTransaction, DEFAULT_PY_TEST_CHAIN_ID, Transaction
from multiprocessing import Pool
from test_framework.mininode import Transactions
import rlp
import sha3

import accounts


class TxParam:
    def __init__(self, sender_index, action=b'', value=0, gas_price=1, gas=21000, data=b'', storage_limit=0,
                 epoch_height=0,
                 chain_id=DEFAULT_PY_TEST_CHAIN_ID):
        self.tx_args = dict(action=action,
                            value=value,
                            gas_price=gas_price,
                            gas=gas,
                            data=data,
                            storage_limit=storage_limit,
                            epoch_height=epoch_height,
                            chain_id=chain_id)
        self.sender_index = sender_index
        self.sender = accounts.map[self.sender_index].address
        self.privkey = accounts.map[self.sender_index].privkey

    def assign_nonce(self):
        self.tx_args["nonce"] = accounts.map[self.sender_index].get_and_inc_nonce()

    def contract_address(self):
        code_hash = sha3.keccak_256(self.tx_args["data"]).digest()
        address = self.sender
        nonce = self.tx_args["nonce"].to_bytes(32, 'little')

        create_hash = sha3.keccak_256(b"\x00" + address + nonce + code_hash).digest()[12:]
        create_hash = (create_hash[0] & 0x0f | 0x80).to_bytes(1, "big") + create_hash[1:]
        return create_hash


class EncodedTransaction:
    def __init__(self, batch_tx):
        self.encoded = rlp.encode(Transactions(transactions=batch_tx))
        self.length = len(batch_tx)


def dump_rpc_batches(txs, fout, batch_size=200, print_hash=False):
    encoded_txs = []
    i = 0
    batch_tx = []
    for tx in txs:
        batch_tx.append(tx)
        i += 1
        if print_hash:
            print("0x" + tx.hash.hex())
        if i % batch_size == 0:
            encoded_txs.append(EncodedTransaction(batch_tx))
            batch_tx = []
    if len(batch_tx) > 0:
        encoded_txs.append(EncodedTransaction(batch_tx))
    pickle.dump(encoded_txs, fout)
