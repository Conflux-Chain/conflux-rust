#!/usr/bin/env python3
from http.client import CannotSendRequest

from eth_utils import decode_hex
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS
from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3

def signed_bytes_to_int256(input):
    v = bytes_to_int(input)
    if v >= 2 ** 255:
        v -= 2 ** 256
    return v

class Issue988Test(ConfluxTestFramework):
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
            ** Issue988Test.REQUEST_BASE
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

    def call_contract_function_rpc(self, contract, name, args, contract_addr):
        func = getattr(contract.functions, name)
        attrs = {}
        gas_price = 1
        gas = CONTRACT_DEFAULT_GAS
        attrs["gas"] = int_to_hex(gas)
        attrs["gasPrice"] = int_to_hex(gas_price)
        attrs["chainId"] = 0
        attrs["to"] = Web3.toChecksumAddress(contract_addr)
        tx = func(*args).buildTransaction(attrs)
        tx["value"] = int_to_hex(tx["value"])
        tx["v"] = "0x0"
        tx["r"] = "0x0"
        tx["s"] = "0x0"
        return self.nodes[0].cfx_call(tx)

    def run_test(self):
        file_dir = os.path.dirname(os.path.realpath(__file__))

        test_contract = get_contract_instance(
            abi_file =os.path.join(file_dir, "contracts/issue988_abi.json"),
            bytecode_file=os.path.join(file_dir, "contracts/issue988_bytecode.dat"),
        )

        start_p2p_connection(self.nodes)

        genesis_key = self.genesis_priv_key
        genesis_addr = self.genesis_addr
        self.log.info("genesis_addr={}".format(encode_hex_0x(genesis_addr)))
        nonce = 0
        gas_price = 1
        gas = CONTRACT_DEFAULT_GAS
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()
        self.tx_conf = {"from":Web3.toChecksumAddress(encode_hex_0x(genesis_addr)), "nonce":int_to_hex(nonce), "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}

        # setup balance for node 0
        node = self.nodes[0]
        client = RpcClient(node)
        (addr, priv_key) = client.rand_account()
        self.log.info("addr=%s priv_key=%s", addr, priv_key)
        tx = client.new_tx(value=20 * 10 ** 18, receiver=addr, nonce=self.get_nonce(genesis_addr))
        client.send_tx(tx, True)
        assert_equal(node.cfx_getBalance(addr), hex(20000000000000000000))

        # deploy test contract
        c0 = client.get_collateral_for_storage(addr)
        tx = self.call_contract_function(
            contract=test_contract,
            name="constructor",
            args=[],
            sender_key=priv_key,
            storage_limit=10604)
        contract_addr = self.wait_for_tx([tx], True)[0]['contractCreated']
        c1 = client.get_collateral_for_storage(addr)
        assert_equal(c1 - c0, 10604 * 10 ** 18 // 1024)
        self.log.info("contract_addr={}".format(contract_addr))
        assert_equal(node.cfx_getBalance(contract_addr), hex(0))

        raw_result = self.call_contract_function_rpc(
            contract=test_contract,
            name="ktrriiwhlx",
            args=[],
            contract_addr=contract_addr)
        result = signed_bytes_to_int256(decode_hex(raw_result))
        assert_equal(result, -12076)

        raw_result = self.call_contract_function_rpc(
            contract=test_contract,
            name="qiwmzrxuhd",
            args=[],
            contract_addr=contract_addr)
        result = signed_bytes_to_int256(decode_hex(raw_result))
        assert_equal(result, -2)

        raw_result = self.call_contract_function_rpc(
            contract=test_contract,
            name="wxqpwecckl",
            args=[],
            contract_addr=contract_addr)
        result = signed_bytes_to_int256(decode_hex(raw_result))
        assert_equal(result, -1)

        self.log.info("Pass")

if __name__ == "__main__":
    Issue988Test().main()
