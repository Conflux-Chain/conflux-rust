#!/usr/bin/env python3
import datetime
import time
import os
import types
import shutil
from eth_utils import decode_hex
from conflux.rpc import RpcClient
from sha3 import keccak_256


from conflux.messages import GetBlockHeaders, GET_BLOCK_HEADERS_RESPONSE
from test_framework.mininode import start_p2p_connection
from test_framework.test_framework import ConfluxTestFramework
from test_framework.blocktools import create_transaction, encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.util import assert_equal, connect_nodes, get_peer_addr, wait_until, WaitHandler, \
    initialize_datadir, PortMin, get_datadir_path
from test_framework.util import *
from test_framework.mininode import *
from test_framework.test_framework import Transactions
from conflux.utils import encode_hex, priv_to_addr, parse_as_int

from web3 import Web3
from web3.exceptions import Web3RPCError

def hex256(value):
    if type(value) is int:
        return value.to_bytes(32,'big').hex()

    raise Exception("unrecognized type")

class Web3Test(ConfluxTestFramework):
    def __init__(self):
        super(Web3Test, self).__init__()
        self.genesis_priv_key = default_config['GENESIS_PRI_KEY']
        self.genesis_addr = priv_to_addr(self.genesis_priv_key)
        self.nonce_map = {}

    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters = {
            "log_level": "\"debug\"",
            "evm_transaction_block_ratio": 1,
            # "public_rpc_apis": "\"cfx,debug,test,pubsub,trace\"",
        }

    def setup_network(self):
        self.setup_nodes()

    def send_transaction(self, transaction, wait, check_status):
        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[transaction]))
        if wait:
            self.wait_for_tx([transaction], check_status)

    def get_nonce(self, sender, inc=True):
        if sender not in self.nonce_map:
            self.nonce_map[sender] = wait_for_initial_nonce_for_address(self.nodes[0], sender)
        else:
            self.nonce_map[sender] += 1
        return self.nonce_map[sender]

    def cross_space_transfer(self, to, value):
        if to.startswith("0x"):
            to = to[2:]
        to = to.lower()
        client = RpcClient(self.nodes[0])
        cross_space = "0x0888000000000000000000000000000000000006"

        data = decode_hex(f"0xda8d5daf{to}000000000000000000000000")
        genesis_addr = self.genesis_addr
        tx = client.new_tx(value=value, receiver=cross_space, data=data, nonce=self.get_nonce(genesis_addr),
                           gas=1000000)
        client.send_tx(tx, True)
        self.wait_for_tx([tx], True)

        receipt = client.get_transaction_receipt(tx.hash.hex())

        call_log = receipt['logs'][0]
        mapped_sender = keccak_256(self.genesis_addr).digest()[-20:].hex()
        assert_equal(mapped_sender, call_log['topics'][1][2:42])
        assert_equal(to, call_log['topics'][2][2:42])
        assert_equal(f"{hex256(value)}{hex256(0)}{hex256(96)}{hex256(0)}",call_log['data'][2:])

        return_log = receipt['logs'][1]
        assert_equal(f"{hex256(1)}",return_log['data'][2:])


    def cross_space_withdraw(self, value):
        client = RpcClient(self.nodes[0])
        cross_space = "0x0888000000000000000000000000000000000006"

        data = decode_hex(f"0xc23ef031{hex256(value)}")
        genesis_addr = self.genesis_addr
        tx = client.new_tx(value=0, receiver=cross_space, data=data, nonce=self.get_nonce(genesis_addr),
                           gas=1000000)
        client.send_tx(tx, True)
        self.wait_for_tx([tx], True)

        receipt = client.get_transaction_receipt(tx.hash.hex())
        log = receipt['logs'][0]
        mapped_sender = keccak_256(self.genesis_addr).digest()[-20:].hex()
        assert_equal(mapped_sender, log['topics'][1][2:42])
        assert_equal(genesis_addr.hex(),log['topics'][2][-40:])
        assert_equal(f"{hex256(value)}{hex256(1)}", log['data'][2:])


    def test_deploy_1820(self):
        client = RpcClient(self.nodes[0])
        cross_space = "0x0888000000000000000000000000000000000006"

        data = decode_hex(f"0x36201722")
        genesis_addr = self.genesis_addr
        tx = client.new_tx(value=0, receiver=cross_space, data=data, nonce=self.get_nonce(genesis_addr),
                           gas=10000000)
        client.send_tx(tx, True)
        self.wait_for_tx([tx], True)

        eip1820 = Web3.to_checksum_address("1820a4b7618bde71dce8cdc73aab6c95905fad24")
        receipt = client.get_transaction_receipt(tx.hash.hex())
        assert_greater_than(int(receipt['gasUsed'],16), 1_500_000 + 21_000)
        assert_equal(len(self.w3.eth.get_code(eip1820)), 2501)

    def run_test(self):
        time.sleep(3)

        self.setup_w3()
        self.w3 = self.ew3

        assert_equal(self.w3.is_connected(), True)
        account = self.w3.eth.account.from_key(
            '0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709')

        sender = account.address

        self.cross_space_transfer(sender, 1 * 10 ** 18)
        assert_equal(1 * 10 ** 18, self.w3.eth.get_balance(sender))

        self.test_deploy_1820()

        # Send eip-155 transaction
        receiver = Web3.to_checksum_address("10000000000000000000000000000000000000aa")
        signed = account.sign_transaction(
            {"to": receiver, "value": 1 * 10 ** 17, "gasPrice": 1, "gas": 21000, "nonce": 0, "chainId": 10})
        tx_hash = signed["hash"]
        return_tx_hash = self.w3.eth.send_raw_transaction(signed["raw_transaction"])
        assert_equal(tx_hash, return_tx_hash)

        client = RpcClient(self.nodes[0])
        client.generate_block(1)
        client.generate_blocks(10)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        assert_equal(receipt["status"], 1)

        # Send pre eip-155 transaction
        signed = account.sign_transaction(
            {"to": receiver, "value": 1 * 10 ** 17, "gasPrice": 1, "gas": 21000, "nonce": 1})
        tx_hash = signed["hash"]
        return_tx_hash = self.w3.eth.send_raw_transaction(signed["raw_transaction"])
        assert_equal(tx_hash, return_tx_hash)

        client.generate_block(1)
        client.generate_blocks(10)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        assert_equal(receipt["status"], 1)

        assert_equal(2 * 10 ** 17, self.w3.eth.get_balance(receiver))
        assert_equal(8 * 10 ** 17 - 42000, self.w3.eth.get_balance(sender))

        # Send to transaction
        mapped_sender = keccak_256(self.genesis_addr).digest()[-20:]
        receiver = Web3.to_checksum_address(mapped_sender.hex())
        signed = account.sign_transaction(
            {"to": receiver, "value": 2 * 10 ** 17, "gasPrice": 1, "gas": 21000, "nonce": 2})
        self.w3.eth.send_raw_transaction(signed["raw_transaction"])

        client = RpcClient(self.nodes[0])
        client.generate_block(1)
        client.generate_blocks(10)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        assert_equal(receipt["status"], 1)

        assert_equal(2 * 10 ** 17, self.w3.eth.get_balance(mapped_sender))

        # Withdraw transaction
        self.cross_space_withdraw(1 * 10 ** 17)

        assert_equal(1 * 10 ** 17, self.w3.eth.get_balance(mapped_sender))

        # Send transaction with large chain-id, should not panic. 
        signed = account.sign_transaction(
            {"to": receiver, "value": 1 * 10 ** 17, "gasPrice": 1, "gas": 21000, "nonce": 3, "chainId": 2**33})
        assert_raises(Web3RPCError, self.w3.eth.send_raw_transaction,signed["raw_transaction"])

        self.nodes[0].test_stop()


if __name__ == "__main__":
    Web3Test().main()
