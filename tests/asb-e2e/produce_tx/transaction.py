import pickle
from enum import Enum
import rlp
import sha3

from .framework import DEFAULT_PY_TEST_CHAIN_ID, Transactions
from .account import get_account

class CallType(Enum):
    Transfer = 0
    Call = 1
    Create = 2

class TxParam:
    def __init__(self, sender_index, action=b'', value=0, gas_price=1, gas = None, data=b'', storage_limit = None,
                 epoch_height=0,
                 chain_id=DEFAULT_PY_TEST_CHAIN_ID):
        if type(data) is str:
            if len(data) >= 2 and data[:2] == "0x":
                data = data[2:]
            data = bytes.fromhex(data)

        call_type = CallType.Transfer
        if len(data) > 0:
            call_type = CallType.Call

        if len(action) == 0:
            call_type = CallType.Create

        if gas is None:
            if call_type == CallType.Transfer:
                gas = 21_000
            elif call_type == CallType.Call:
                gas = 300_000
            elif call_type == CallType.Create:
                gas = 13_000_000

        if storage_limit is None:
            if call_type == CallType.Transfer:
                storage_limit = 0
            elif call_type == CallType.Call:
                storage_limit = 512
            elif call_type == CallType.Create:
                storage_limit = int(len(data) * 1.5)


        self.tx_args = dict(action=action,
                            value=value,
                            gas_price=gas_price,
                            gas=gas,
                            data=data,
                            storage_limit=storage_limit,
                            epoch_height=epoch_height,
                            chain_id=chain_id)
        self.sender_index = sender_index
        sender_account = get_account(self.sender_index)
        self.sender = sender_account.address
        self.privkey = sender_account.privkey

    def set_gas(self, gas = None, storage_limit = None):
        if gas is not None:
            self.tx_args["gas"] = gas
        
        if storage_limit is not None:
            self.tx_args["storage_limit"] = storage_limit

    def set_value(self, value = 0, decimals = 18):
        self.tx_args["value"] = value * (10 ** decimals)

    def assign_nonce(self):
        if "nonce" in self.tx_args:
            raise Exception("nonce has been inited")
        
        self.tx_args["nonce"] = get_account(self.sender_index).get_and_inc_nonce()

    def contract_address(self):
        if "nonce" not in self.tx_args:
            raise Exception("Have not assign nonce")
        
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
