#!/usr/bin/env python3
from integration_tests.test_framework.blocktools import create_transaction, wait_for_initial_nonce_for_address
from eth_utils.hexadecimal import decode_hex
from integration_tests.test_framework.block_gen_thread import BlockGenThread
from integration_tests.test_framework.util import *
from integration_tests.test_framework.mininode import *
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.transactions import CONTRACT_DEFAULT_GAS
from integration_tests.conflux.utils import ec_random_keys, priv_to_addr, encode_hex_0x


class SmartContractBenchBase(ConfluxTestFramework):
    REQUEST_BASE = {
        'gas': CONTRACT_DEFAULT_GAS,
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
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()
        sync_blocks(self.nodes)

    def setup_contract(self):
        pass

    def generate_transactions(self, i):
        pass

    def run_test(self):
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
        self.default_account_address = priv_to_addr(self.default_account_key)

    def get_nonce(self, sender):
        if sender not in self.nonce_map:
            self.nonce_map[sender] = wait_for_initial_nonce_for_address(self.nodes[0], sender)
        else:
            self.nonce_map[sender] += 1
        return self.nonce_map[sender]

    def call_contract_function(self, contract, name, args, sender_key, contract_addr=None, wait=False,
                               check_status=False, storage_limit=0):
        # If contract address is empty, call the constructor.
        if contract_addr:
            func = getattr(contract.functions, name)
        else:
            func = getattr(contract, name)
        attributes = {
            'nonce': self.get_nonce(priv_to_addr(sender_key)),
            ** SmartContractBenchBase.REQUEST_BASE
        }
        if contract_addr:
            attributes['receiver'] = decode_hex(contract_addr)
            attributes['to'] = contract_addr
        else:
            attributes['receiver'] = b''
        tx_data = func(*args).build_transaction(attributes)
        tx_data['data'] = decode_hex(tx_data['data'])
        tx_data['pri_key'] = sender_key
        tx_data['gas_price'] = tx_data['gasPrice']
        tx_data['storage_limit'] = storage_limit
        tx_data.pop('gasPrice', None)
        tx_data.pop('chainId', None)
        tx_data.pop('to', None)
        transaction = create_transaction(**tx_data)
        self._send_transaction(transaction, wait, check_status)
        return transaction

    def new_address_and_transfer(self, count=1, amount=int(1e22), wait=False, check_status=False):
        results = []
        for _ in range(count):
            pri_key, pub_key = ec_random_keys()
            transaction = self.transfer(self.default_account_key, priv_to_addr(pri_key), amount, wait, check_status)
            results.append([pri_key, transaction])
        return results

    def transfer(self, sender_key, receiver, amount, wait=False, check_status=False):
        nonce = self.get_nonce(priv_to_addr(sender_key))
        transaction = create_transaction(nonce, 1, 21000, amount, receiver, pri_key=sender_key)
        self._send_transaction(transaction, wait, check_status)
        return transaction

    def _send_transaction(self, transaction, wait, check_status):
        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[transaction]))
        if wait:
            self.wait_for_tx([transaction], check_status)
