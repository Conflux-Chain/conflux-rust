#!/usr/bin/env python3
from test_framework.blocktools import create_transaction
from conflux.messages import Transactions
from eth_utils import decode_hex
from test_framework.block_gen_thread import BlockGenThread
from test_framework.util import *
from test_framework.mininode import *
from test_framework.test_framework import ConfluxTestFramework
from conflux.rpc import RpcClient
from conflux.utils import ec_random_keys, privtoaddr, encode_hex_0x
from http.client import CannotSendRequest


class SmartContractBenchBase(ConfluxTestFramework):
    REQUEST_BASE = {
        'gas': 50000000,
        'gasPrice': 1,
        'chainId': 1,
    }

    def add_options(self, parser):
        parser.add_argument(
            "--iter",
            dest="iter",
            default=1,
            type=int,
            help=
            "The number of iterations the benchmark will be executed."
        )

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()
        sync_blocks(self.nodes)

    def setup_contract(self):
        pass

    def generate_transactions(self, i):
        pass

    def run_test(self):
        # Prevent easysolc from configuring the root logger to print to stderr
        self.log.propagate = False

        start_p2p_connection(self.nodes)
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        self.setup_contract()
        for i in range(self.options.iter):
            self.generate_transactions(i)

    def __init__(self):
        super().__init__()
        self.nonce_map = {}
        self.default_account_key = default_config["GENESIS_PRI_KEY"]
        self.default_account_address = privtoaddr(self.default_account_key)

    def get_nonce(self, sender):
        sender = sender.lower()
        if sender not in self.nonce_map:
            self.nonce_map[sender] = 0
        else:
            self.nonce_map[sender] += 1
        return self.nonce_map[sender]

    def call_contract_function(self, contract, name, args, sender_key, contract_addr=None, wait=False,
                               check_status=False):
        # If contract address is empty, call the constructor.
        if contract_addr:
            func = getattr(contract.functions, name)
        else:
            func = getattr(contract, name)
        attributes = {
            'nonce': self.get_nonce(privtoaddr(sender_key)),
            ** SmartContractBenchBase.REQUEST_BASE
        }
        if contract_addr:
            attributes['receiver'] = decode_hex(contract_addr)
            attributes['to'] = contract_addr
        else:
            attributes['receiver'] = b''
        tx_data = func(*args).buildTransaction(attributes)
        tx_data['data'] = decode_hex(tx_data['data'])
        tx_data['pri_key'] = sender_key
        tx_data['gas_price'] = tx_data['gasPrice']
        tx_data.pop('gasPrice', None)
        tx_data.pop('chainId', None)
        tx_data.pop('to', None)
        transaction = create_transaction(**tx_data)
        self._send_transaction(transaction, wait, check_status)
        return transaction

    def new_address_and_transfer(self, count=1, amount=100000000000000, wait=False, check_status=False):
        results = []
        for _ in range(count):
            pri_key, pub_key = ec_random_keys()
            transaction = self.transfer(self.default_account_key, privtoaddr(pri_key), amount, wait, check_status)
            results.append([pri_key, transaction])
        return results

    def transfer(self, sender_key, receiver, amount, wait=False, check_status=False):
        nonce = self.get_nonce(privtoaddr(sender_key))
        transaction = create_transaction(nonce, 1, 21000, amount, receiver, pri_key=sender_key)
        self._send_transaction(transaction, wait, check_status)
        return transaction

    def _send_transaction(self, transaction, wait, check_status):
        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[transaction]))
        if wait:
            self.wait_for_tx([transaction], check_status)

    def wait_for_tx(self, all_txs, check_status):
        for tx in all_txs:
            for i in range(3):
                try:
                    retry = True
                    while retry:
                        try:
                            wait_until(lambda: checktx(self.nodes[0], tx.hash_hex()), timeout=20)
                            retry = False
                        except CannotSendRequest:
                            time.sleep(0.01)
                    break
                except AssertionError as _:
                    self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[tx]))
                if i == 2:
                    raise AssertionError("Tx {} not confirmed after 30 seconds".format(tx.hash_hex()))
        # After having optimistic execution, get_receipts may get receipts with not deferred block, these extra blocks
        # ensure that later get_balance can get correct executed balance for all transactions
        client = RpcClient(self.nodes[0])
        for _ in range(5):
            client.generate_block()
        receipts = [client.get_transaction_receipt(tx.hash_hex()) for tx in all_txs]
        self.log.debug("Receipts received: {}".format(receipts))
        if check_status:
            map(lambda x: assert_equal(x['outcomeStatus'], 0), receipts)
        return receipts

