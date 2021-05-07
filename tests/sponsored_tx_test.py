#!/usr/bin/env python3
from eth_utils import decode_hex

from conflux.address import hex_to_b32_address
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS, COLLATERAL_UNIT_IN_DRIP, charged_of_huge_gas
from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3

class SponsoredTxTest(ConfluxTestFramework):
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
                               storage_limit=0,
                               gas=None):
        if contract_addr:
            func = getattr(contract.functions, name)
        else:
            func = getattr(contract, name)
        attrs = {
            'nonce': self.get_nonce(priv_to_addr(sender_key)),
            ** SponsoredTxTest.REQUEST_BASE
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
        if gas is not None:
            tx_data['gas'] = gas
        transaction = create_transaction(**tx_data)
        self.send_transaction(transaction, wait, check_status)
        return transaction

    def run_test(self):
        sponsor_whitelist_contract_addr = Web3.toChecksumAddress("0888000000000000000000000000000000000001")
        collateral_per_storage_key = COLLATERAL_UNIT_IN_DRIP * 64
        upper_bound = 5 * 10 ** 7

        file_dir = os.path.dirname(os.path.realpath(__file__))

        control_contract_file_path =os.path.join(file_dir, "..", "internal_contract", "metadata", "SponsorWhitelistControl.json")
        control_contract_dict = json.loads(open(control_contract_file_path, "r").read())

        control_contract = get_contract_instance(contract_dict=control_contract_dict)

        test_contract = get_contract_instance(
            abi_file=os.path.join(file_dir, "contracts/commission_privilege_test_abi.json"),
            bytecode_file=os.path.join(file_dir, "contracts/commission_privilege_test_bytecode.dat"),
        )

        start_p2p_connection(self.nodes)

        self.log.info("Initializing contract")
        genesis_key = self.genesis_priv_key
        genesis_addr = encode_hex(self.genesis_addr)
        self.log.info("genesis_addr={}".format(genesis_addr))
        nonce = 0
        gas_price = 1
        gas = CONTRACT_DEFAULT_GAS
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()
        self.tx_conf = {
            "from": Web3.toChecksumAddress(genesis_addr),
            "nonce": int_to_hex(nonce),
            "gas": int_to_hex(gas),
            "gasPrice": int_to_hex(gas_price),
            "chainId": 0
        }

        # Setup balance for node 0
        node = self.nodes[0]
        client = RpcClient(node)
        (addr1, priv_key1) = client.rand_account()
        self.log.info("addr1={}".format(addr1))
        tx = client.new_tx(
            sender=genesis_addr,
            priv_key=genesis_key,
            value=10 ** 6,
            nonce=self.get_nonce(self.genesis_addr),
            receiver=addr1)
        client.send_tx(tx, True)
        assert_equal(client.get_balance(addr1), 10 ** 6)

        # setup contract
        transaction = self.call_contract_function(
            contract=test_contract,
            name="constructor",
            args=[],
            sender_key=self.genesis_priv_key,
            storage_limit=20000)
        contract_addr = self.wait_for_tx([transaction], True)[0]['contractCreated']
        self.log.info("contract_addr={}".format(contract_addr))
        assert_equal(client.get_balance(contract_addr), 0)

        # sponsor the contract succeed
        b0 = client.get_balance(genesis_addr)
        self.call_contract_function(
            contract=control_contract,
            name="setSponsorForGas",
            args=[Web3.toChecksumAddress(contract_addr), upper_bound],
            value=10 ** 18,
            sender_key=self.genesis_priv_key,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr)
        assert_equal(client.get_sponsor_gas_bound(contract_addr), upper_bound)
        assert_equal(client.get_balance(genesis_addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))

        # set privilege for addr1
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        transaction = self.call_contract_function(
            contract=test_contract,
            name="add",
            args=[Web3.toChecksumAddress(addr1)],
            sender_key=genesis_key,
            contract_addr=contract_addr,
            wait=True,
            check_status=True,
            storage_limit=64)
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) - collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + collateral_per_storage_key)
        assert_equal(self.wait_for_tx([transaction], True)[0]['gasCoveredBySponsor'], False)

        # addr1 call contract with privilege without enough cfx for gas fee
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        transaction = self.call_contract_function(
            contract=test_contract,
            name="foo",
            args=[],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            wait=True,
            check_status=True)
        assert_equal(client.get_balance(addr1), b1)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - charged_of_huge_gas(gas))
        assert_equal(self.wait_for_tx([transaction], True)[0]['gasCoveredBySponsor'], True)

        # sponsor collateral for the contract succeed
        b0 = client.get_balance(genesis_addr)
        self.call_contract_function(
            contract=control_contract,
            name="setSponsorForCollateral",
            args=[Web3.toChecksumAddress(contract_addr)],
            value=10 ** 18,  # 1 CFX = 1KB
            sender_key=self.genesis_priv_key,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), genesis_addr)
        assert_equal(client.get_balance(genesis_addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))

        # addr1 call contract with privilege without enough cfx for storage
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        transaction = self.call_contract_function(
            contract=test_contract,
            name="foo",
            args=[],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            wait=True,
            check_status=True,
            storage_limit=1024)
        assert_equal(client.get_balance(addr1), b1)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - charged_of_huge_gas(gas))
        assert_equal(self.wait_for_tx([transaction], True)[0]['storageCoveredBySponsor'], True)

        # addr1 call with larger storage limit, should not packed
        transaction = self.call_contract_function(
            contract=test_contract,
            name="foo",
            args=[],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            storage_limit=1025)
        for _ in range(10):
            client.generate_block()

        tx_info = self.nodes[0].tx_inspect(transaction.hash_hex())
        assert_equal(int(tx_info['local_nonce'], 16), 2)
        assert_equal(tx_info['local_balance_enough'], False)
        assert_equal(tx_info['packed'], False)

        # send 1025 * 10 ** 18 // 1024 CFX to addr1
        tx = client.new_tx(
            sender=genesis_addr,
            priv_key=genesis_key,
            value=1025 * 10 ** 18 // 1024,
            nonce=self.get_nonce(self.genesis_addr),
            receiver=addr1)
        client.send_tx(tx, True)
        assert_equal(client.get_balance(addr1), 10 ** 6 + 1025 * 10 ** 18 // 1024)
        for _ in range(10):
            client.generate_block()
        tx_info = self.nodes[0].tx_inspect(transaction.hash_hex())
        assert_equal(self.wait_for_tx([transaction], True)[0]['storageCoveredBySponsor'], True)
        assert_equal(int(tx_info['local_nonce'], 16), 3)
        assert_equal(tx_info['packed'], True)

        self.log.info("Pass")


if __name__ == "__main__":
    SponsoredTxTest().main()
