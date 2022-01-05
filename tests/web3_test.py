#!/usr/bin/env python3
import datetime
import time
import os
import types
import shutil
from eth_utils import decode_hex
from conflux.rpc import RpcClient

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
            # "public_rpc_apis": "\"cfx,evm,debug,test,pubsub,trace\"",
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

    def run_test(self):
        time.sleep(3)

        ip = self.nodes[0].ip
        port = self.nodes[0].rpcport
        self.w3 = Web3(Web3.HTTPProvider(f'http://{ip}:{port}/'))

        assert_equal(self.w3.isConnected(), True)
        account = self.w3.eth.account.privateKeyToAccount(
            '0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709')

        sender = account.address

        self.cross_space_transfer(sender, 1 * 10 ** 18)
        assert_equal(1 * 10 ** 18, self.w3.eth.get_balance(sender))

        receiver = Web3.toChecksumAddress("10000000000000000000000000000000000000aa")
        signed = account.signTransaction(
            {"to": receiver, "value": 5 * 10 ** 17, "gasPrice": 1, "gas": 21000, "nonce": 0, "chainId": 10})
        tx_hash = signed["hash"]
        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        assert_equal(tx_hash, return_tx_hash)

        client = RpcClient(self.nodes[0])
        client.generate_block(1)
        client.generate_blocks(10)
        receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        assert_equal(receipt["status"], 1)

        assert_equal(5 * 10 ** 17, self.w3.eth.get_balance(receiver))
        assert_equal(5 * 10 ** 17 - 21000, self.w3.eth.get_balance(sender))

        self.nodes[0].stop()


if __name__ == "__main__":
    Web3Test().main()
