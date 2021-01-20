#!/usr/bin/env python3
from eth_utils import decode_hex
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS, charged_of_huge_gas
from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3

class AdminControlTest(ConfluxTestFramework):
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
            ** AdminControlTest.REQUEST_BASE
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
        tx_data['storage_limit'] = storage_limit
        transaction = create_transaction(**tx_data)
        self.send_transaction(transaction, wait, check_status)
        return transaction

    def run_test(self):
        file_dir = os.path.dirname(os.path.realpath(__file__))

        pay_contract = get_contract_instance(
            abi_file=os.path.join(file_dir, "contracts/pay_abi.json"),
            bytecode_file=os.path.join(file_dir, "contracts/pay_bytecode.dat"),
        )

        control_contract_file_path =os.path.join(file_dir, "../internal_contract/metadata/AdminControl.json")
        control_contract_dict = json.loads(open(control_contract_file_path, "r").read())

        admin_control_contract = get_contract_instance(contract_dict=control_contract_dict)

        start_p2p_connection(self.nodes)

        self.log.info("Initializing contract")
        genesis_key = self.genesis_priv_key
        genesis_addr = self.genesis_addr
        self.log.info("genesis_addr={}".format(encode_hex_0x(genesis_addr)))
        nonce = 0
        gas_price = 1
        gas = CONTRACT_DEFAULT_GAS
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()
        self.tx_conf = {"from":Web3.toChecksumAddress(encode_hex_0x(genesis_addr)), "nonce":int_to_hex(nonce), "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}

        # Setup balance for node 0
        node = self.nodes[0]
        client = RpcClient(node)
        (addr, priv_key) = client.rand_account()
        self.log.info("addr=%s priv_key=%s", addr, priv_key)
        tx = client.new_tx(value=5 * 10 ** 18, receiver=addr, nonce=self.get_nonce(genesis_addr))
        client.send_tx(tx, True)
        assert_equal(client.get_balance(addr), 5000000000000000000)

        (addr2, priv_key2) = client.rand_account()
        self.log.info("addr2=%s priv_key2=%s", addr2, priv_key2)
        tx = client.new_tx(value=5 * 10 ** 18, receiver=addr2, nonce=self.get_nonce(genesis_addr))
        client.send_tx(tx, True)
        assert_equal(client.get_balance(addr2), 5000000000000000000)

        # deploy pay contract
        tx = self.call_contract_function(
            contract=pay_contract,
            name="constructor",
            args=[],
            sender_key=priv_key,
            storage_limit=512)
        contract_addr = self.wait_for_tx([tx], True)[0]['contractCreated']
        self.log.info("contract_addr={}".format(contract_addr))
        assert_equal(client.get_collateral_for_storage(addr), 512 * 976562500000000)
        assert_equal(client.get_balance(contract_addr), 0)

        # deposit 10**18
        b0 = client.get_balance(addr)
        tx = self.call_contract_function(
            contract=pay_contract,
            name="recharge",
            args=[],
            sender_key=priv_key,
            contract_addr=contract_addr,
            value=10 ** 18,
            wait=True,
            check_status=True)
        assert_equal(client.get_balance(contract_addr), 10 ** 18)
        assert_equal(client.get_balance(addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))
        assert_equal(client.get_admin(contract_addr), addr)

        # transfer admin (fail)
        tx = self.call_contract_function(
            contract=admin_control_contract,
            name="setAdmin",
            args=[Web3.toChecksumAddress(contract_addr), Web3.toChecksumAddress(addr2)],
            sender_key=priv_key2,
            contract_addr=Web3.toChecksumAddress("0x0888000000000000000000000000000000000000"),
            wait=True,
            check_status=True)
        assert_equal(client.get_admin(contract_addr), addr)
        assert_equal(client.get_balance(addr2), 5 * 10 ** 18 - charged_of_huge_gas(gas))

        # transfer admin (success)
        tx = self.call_contract_function(
            contract=admin_control_contract,
            name="setAdmin",
            args=[Web3.toChecksumAddress(contract_addr), Web3.toChecksumAddress(addr2)],
            sender_key=priv_key,
            contract_addr=Web3.toChecksumAddress("0x0888000000000000000000000000000000000000"),
            wait=True,
            check_status=True)
        assert_equal(client.get_admin(contract_addr), addr2)

        # destroy
        b0 = client.get_balance(addr)
        tx = self.call_contract_function(
            contract=admin_control_contract,
            name="destroy",
            args=[Web3.toChecksumAddress(contract_addr)],
            sender_key=priv_key2,
            contract_addr=Web3.toChecksumAddress("0x0888000000000000000000000000000000000000"),
            wait=True,
            check_status=True)
        assert_equal(client.get_balance(contract_addr), 0)
        assert_equal(client.get_balance(addr2), 6 * 10 ** 18 - charged_of_huge_gas(gas) * 2)
        assert_equal(client.get_collateral_for_storage(addr), 0)
        assert_equal(client.get_balance(addr), b0 + 512 * 976562500000000)

        self.log.info("Pass")

if __name__ == "__main__":
    AdminControlTest().main()
