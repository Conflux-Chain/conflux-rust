#!/usr/bin/env python3

from conflux.utils import privtoaddr, parse_as_int
from conflux.rpc import RpcClient
from http.client import CannotSendRequest
from test_framework.util import *
from test_framework.mininode import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.blocktools import create_transaction
from test_framework.block_gen_thread import BlockGenThread
from eth_utils import decode_hex
from easysolc import Solc
from web3 import Web3
import copy

class ReentrancyTest(ConfluxTestFramework):
    REQUEST_BASE = {
        'gas': 50000000,
        'gasPrice': 1,
        'chainId': 1,
    }

    def __init__(self):
        super().__init__()

        self.nonce_map = {}
        self.genesis_priv_key = default_config['GENESIS_PRI_KEY']
        self.genesis_addr = privtoaddr(self.genesis_priv_key)
        self.balance_map = {self.genesis_priv_key: default_config['TOTAL_COIN']}

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()
        sync_blocks(self.nodes)

    def get_nonce(self, sender, inc=True):
        sender = sender.lower()
        if sender not in self.nonce_map:
            self.nonce_map[sender] = 0
        else:
            self.nonce_map[sender] += 1
        return self.nonce_map[sender]

    def send_transaction(self, transaction, wait, check_status):
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
        receipts = [self.nodes[0].gettransactionreceipt(tx.hash_hex()) for tx in all_txs]
        self.log.debug("Receipts received: {}".format(receipts))
        if check_status:
            map(lambda x: assert_equal(x['outcomeStatus'], 0), receipts)
        return receipts

    def call_contract_function(self, contract, name, args, sender_key, value=None,
                               contract_addr=None, wait=False,
                               check_status=False):
        if contract_addr:
            func = getattr(contract.functions, name)
        else:
            func = getattr(contract, name)
        attrs = {
            'nonce': self.get_nonce(privtoaddr(sender_key)),
            ** ReentrancyTest.REQUEST_BASE
        }
        if contract_addr:
            attrs['receiver'] = decode_hex(contract_addr)
            attrs['to'] = contract_addr
        else:
            attrs['receiver'] = b''
        tx_data = func(*args).buildTransaction(attrs)
        tx_data['data'] = decode_hex(tx_data['data'])
        tx_data['pri_key'] = sender_key
        tx_data['gas_price'] = tx_data['gasPrice']
        if value:
            tx_data['value'] = value
        tx_data.pop('gasPrice', None)
        tx_data.pop('chainId', None)
        tx_data.pop('to', None)
        transaction = create_transaction(**tx_data)
        self.send_transaction(transaction, wait, check_status)
        return transaction

    def run_test(self):
        self.log.propagate = False

        start_p2p_connection(self.nodes)
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))

        self.log.info("Initializing contract")
       
        self.buggy_contract = solc.get_contract_instance(
            source=os.path.join(file_dir, "contracts/reentrancy.sol"),
            contract_name="Reentrance")
        self.exploit_contract = solc.get_contract_instance(
            source=os.path.join(file_dir, "contracts/reentrancy_exploit.sol"),
            contract_name="ReentranceExploit")

        user1, _ = ec_random_keys()
        user1_addr = privtoaddr(user1)
        user2, _ = ec_random_keys()
        user2_addr = privtoaddr(user2)

        # setup balance
        value = (10 ** 15 + 2000) * 10 ** 18 + ReentrancyTest.REQUEST_BASE['gas']
        tx = create_transaction(
            pri_key=self.genesis_priv_key,
            receiver=user1_addr,
            value=value,
            nonce=self.get_nonce(self.genesis_addr),
            gas_price=ReentrancyTest.REQUEST_BASE['gas'])
        self.send_transaction(tx, True, False)

        tx = create_transaction(
            pri_key=self.genesis_priv_key,
            receiver=user2_addr,
            value=value,
            nonce=self.get_nonce(self.genesis_addr),
            gas_price=ReentrancyTest.REQUEST_BASE['gas'])
        self.send_transaction(tx, True, False)

        addr = eth_utils.encode_hex(user1_addr)
        balance = parse_as_int(self.nodes[0].cfx_getBalance(addr))
        assert_equal(balance, value)
        addr = eth_utils.encode_hex(user2_addr)
        balance = parse_as_int(self.nodes[0].cfx_getBalance(addr))
        assert_equal(balance, value)

        # lock balance in bank
        node = self.nodes[0]
        client = RpcClient(node)
        staking_contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/storage_interest_staking_abi.json"),
            bytecode_file = os.path.join(file_dir, "contracts/storage_interest_staking_bytecode.dat"),
        )
        staking_contract_addr = Web3.toChecksumAddress("443c409373ffd5c0bec1dddb7bec830856757b65")
        tx_conf = copy.deepcopy(ReentrancyTest.REQUEST_BASE)
        tx_conf['to'] = staking_contract_addr
        tx_data = decode_hex(staking_contract.functions.deposit(2000 * 10 ** 18).buildTransaction(tx_conf)["data"])
        tx1 = client.new_tx(
            value=0,
            sender=eth_utils.encode_hex(user1_addr),
            receiver=staking_contract_addr,
            nonce=self.get_nonce(user1_addr),
            data=tx_data,
            gas=ReentrancyTest.REQUEST_BASE['gas'],
            gas_price=ReentrancyTest.REQUEST_BASE['gasPrice'],
            priv_key=eth_utils.encode_hex(user1))
        tx2 = client.new_tx(
            value=0,
            sender=eth_utils.encode_hex(user2_addr),
            receiver=staking_contract_addr,
            nonce=self.get_nonce(user2_addr),
            data=tx_data,
            gas=ReentrancyTest.REQUEST_BASE['gas'],
            gas_price=ReentrancyTest.REQUEST_BASE['gasPrice'],
            priv_key=eth_utils.encode_hex(user2))
        client.send_tx(tx1)
        client.send_tx(tx2)
        self.wait_for_tx([tx1, tx2], False)

        transaction = self.call_contract_function(self.buggy_contract, "constructor", [], self.genesis_priv_key)
        contract_addr = self.wait_for_tx([transaction], True)[0]['contractCreated']

        transaction = self.call_contract_function(self.exploit_contract, "constructor", [], user2)
        exploit_addr = self.wait_for_tx([transaction], True)[0]['contractCreated']

        transaction = self.call_contract_function(self.buggy_contract, "addBalance", [], user1, 100000000000000000000000000000000,
                                                  contract_addr, True, True)
        transaction = self.call_contract_function(self.exploit_contract, "deposit", [Web3.toChecksumAddress(contract_addr)], user2, 100000000000000000000000000000000,
                                                  exploit_addr, True, True)

        addr = eth_utils.encode_hex(user1_addr)
        balance = parse_as_int(self.nodes[0].cfx_getBalance(addr))
        assert_greater_than_or_equal(balance, 899999999999999999999999950000000)
        addr = eth_utils.encode_hex(user2_addr)
        balance = parse_as_int(self.nodes[0].cfx_getBalance(addr))
        assert_greater_than_or_equal(balance, 899999999999999999999999900000000)
        balance = parse_as_int(self.nodes[0].cfx_getBalance(contract_addr))
        assert_equal(balance, 200000000000000000000000000000000)

        transaction = self.call_contract_function(self.exploit_contract, "launch_attack", [], user2, 0,
                                                  exploit_addr, True, True)
        transaction = self.call_contract_function(self.exploit_contract, "get_money", [], user2, 0,
                                                  exploit_addr, True, True)

        addr = eth_utils.encode_hex(user1_addr)
        balance = parse_as_int(self.nodes[0].cfx_getBalance(addr))
        assert_greater_than_or_equal(balance, 899999999999999999999999950000000)
        addr = eth_utils.encode_hex(user2_addr)
        balance = parse_as_int(self.nodes[0].cfx_getBalance(addr))
        assert_greater_than_or_equal(balance, 1099999999999999999999999800000000)
        balance = parse_as_int(self.nodes[0].cfx_getBalance(contract_addr))
        assert_equal(balance, 0)

        block_gen_thread.stop()
        block_gen_thread.join()

if __name__ == '__main__':
    ReentrancyTest().main()
