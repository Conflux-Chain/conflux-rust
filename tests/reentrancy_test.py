#!/usr/bin/env python3

from conflux.utils import priv_to_addr, parse_as_int
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS
from http.client import CannotSendRequest
from test_framework.util import *
from test_framework.mininode import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.blocktools import create_transaction, wait_for_initial_nonce_for_address
from test_framework.block_gen_thread import BlockGenThread
from eth_utils import decode_hex
from web3 import Web3

class ReentrancyTest(ConfluxTestFramework):
    REQUEST_BASE = {
        'gas': CONTRACT_DEFAULT_GAS,
        'gasPrice': 1,
        'chainId': 1,
    }

    def __init__(self):
        super().__init__()

        self.nonce_map = {}
        self.genesis_priv_key = default_config['GENESIS_PRI_KEY']
        self.genesis_addr = priv_to_addr(self.genesis_priv_key)
        self.balance_map = {self.genesis_priv_key: default_config['TOTAL_COIN']}

    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()
        sync_blocks(self.nodes)

    def get_nonce(self, sender, inc=True):
        if sender not in self.nonce_map:
            self.nonce_map[sender] = wait_for_initial_nonce_for_address(self.nodes[0], sender)
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
        receipts = [client.get_transaction_receipt(tx.hash_hex()) for tx in all_txs]
        self.log.debug("Receipts received: {}".format(receipts))
        if check_status:
            map(lambda x: assert_equal(x['outcomeStatus'], 0), receipts)
        return receipts

    def call_contract_function(self, contract, name, args, sender_key, value=None,
                               contract_addr=None, wait=False,
                               check_status=False,
                               storage_limit=0):
        if contract_addr:
            func = getattr(contract.functions, name)
        else:
            func = getattr(contract, name)
        attrs = {
            'nonce': self.get_nonce(priv_to_addr(sender_key)),
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
        tx_data['storage_limit'] = storage_limit
        if value:
            tx_data['value'] = value
        tx_data.pop('gasPrice', None)
        tx_data.pop('chainId', None)
        tx_data.pop('to', None)
        transaction = create_transaction(**tx_data)
        self.send_transaction(transaction, wait, check_status)
        return transaction

    def run_test(self):
        start_p2p_connection(self.nodes)
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        file_dir = os.path.dirname(os.path.realpath(__file__))

        self.log.info("Initializing contract")
       
        self.buggy_contract = get_contract_instance(
            source=os.path.join(file_dir, "contracts/reentrancy.sol"),
            contract_name="Reentrance")
        self.exploit_contract = get_contract_instance(
            source=os.path.join(file_dir, "contracts/reentrancy_exploit.sol"),
            contract_name="ReentranceExploit")

        user1, _ = ec_random_keys()
        user1_addr = priv_to_addr(user1)
        user1_addr_hex = eth_utils.encode_hex(user1_addr)
        user2, _ = ec_random_keys()
        user2_addr = priv_to_addr(user2)
        user2_addr_hex = eth_utils.encode_hex(user2_addr)

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

        user1_balance = parse_as_int(self.nodes[0].cfx_getBalance(user1_addr_hex))
        assert_equal(user1_balance, value)
        user2_balance_before_contract_construction = parse_as_int(self.nodes[0].cfx_getBalance(user2_addr_hex))
        assert_equal(user2_balance_before_contract_construction, value)

        transaction = self.call_contract_function(self.buggy_contract, "constructor", [], self.genesis_priv_key, storage_limit=20000)
        contract_addr = self.wait_for_tx([transaction], True)[0]['contractCreated']

        transaction = self.call_contract_function(self.exploit_contract, "constructor", [], user2, storage_limit=200000)
        exploit_addr = self.wait_for_tx([transaction], True)[0]['contractCreated']
        user2_balance_after_contract_construction = parse_as_int(self.nodes[0].cfx_getBalance(user2_addr_hex))
        self.log.debug("user2 balance contract created %s" % user2_balance_after_contract_construction)
        assert_greater_than_or_equal(user2_balance_before_contract_construction, user2_balance_after_contract_construction)
        user2_refund_upper_bound = \
            user2_balance_before_contract_construction - \
            user2_balance_after_contract_construction

        transaction = self.call_contract_function(self.buggy_contract, "addBalance", [], user1, 10 ** 18,
                                                  contract_addr, True, True, storage_limit=128)
        transaction = self.call_contract_function(self.exploit_contract, "deposit", [Web3.toChecksumAddress(contract_addr)], user2, 10 ** 18,
                                                  exploit_addr, True, True, storage_limit=128)

        user1_balance = parse_as_int(self.nodes[0].cfx_getBalance(user1_addr_hex))
        assert_greater_than_or_equal(user1_balance, 899999999999999999999999950000000)
        user2_balance_after_deposit = parse_as_int(self.nodes[0].cfx_getBalance(user2_addr_hex))
        # User2 paid storage collateral `vulnerable_contract` in deposit call.
        user2_refund_upper_bound += 10 ** 18 // 16
        self.log.debug("user2 balance after deposit %s" % user2_balance_after_deposit)
        assert_greater_than_or_equal(user2_balance_after_contract_construction, user2_balance_after_deposit + 10 ** 18)
        assert_greater_than_or_equal(user2_balance_after_deposit, 899999999999999999999999900000000)
        contract_balance = parse_as_int(self.nodes[0].cfx_getBalance(contract_addr))
        assert_equal(contract_balance, 2 * 10 ** 18)
        user2_balance_in_contract = RpcClient(self.nodes[0]).call(
            contract_addr,
            self.buggy_contract.functions.balanceOf(Web3.toChecksumAddress(exploit_addr)).buildTransaction(
                {"from":user2_addr_hex, "to":contract_addr, "gas":int_to_hex(CONTRACT_DEFAULT_GAS), "gasPrice":int_to_hex(1), "chainId":0}
            )["data"])
        assert_equal(parse_as_int(user2_balance_in_contract), 10 ** 18)

        transaction = self.call_contract_function(self.exploit_contract, "launch_attack", [], user2, 0,
                                                  exploit_addr, True, True, storage_limit=128)
        transaction = self.call_contract_function(self.exploit_contract, "get_money", [], user2, 0,
                                                  exploit_addr, True, True, storage_limit=128)

        user1_balance = parse_as_int(self.nodes[0].cfx_getBalance(user1_addr_hex))
        assert_greater_than_or_equal(user1_balance, 899999999999999999999999950000000)
        contract_balance = parse_as_int(self.nodes[0].cfx_getBalance(contract_addr))
        assert_equal(contract_balance, 2 * 10 ** 18)
        user2_balance_in_contract = RpcClient(self.nodes[0]).call(
            contract_addr,
            self.buggy_contract.functions.balanceOf(Web3.toChecksumAddress(exploit_addr)).buildTransaction(
                {"from":user2_addr_hex, "to":contract_addr, "gas":int_to_hex(CONTRACT_DEFAULT_GAS), "gasPrice":int_to_hex(1), "chainId":0}
            )["data"])
        assert_equal(parse_as_int(user2_balance_in_contract), 10 ** 18)
        self.log.debug("user2 balance in contract %s" % user2_balance_in_contract)
        user2_balance_after_contract_destruct = parse_as_int(self.nodes[0].cfx_getBalance(user2_addr_hex))
        self.log.debug("user2 balance after contract destruct %s" % user2_balance_after_contract_destruct)
        assert_greater_than_or_equal(
            user2_balance_after_deposit + user2_refund_upper_bound,
            user2_balance_after_contract_destruct)

        block_gen_thread.stop()
        block_gen_thread.join()

if __name__ == '__main__':
    ReentrancyTest().main()
