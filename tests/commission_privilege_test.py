#!/usr/bin/env python3
from http.client import CannotSendRequest
from eth_utils import decode_hex

from conflux.rpc import RpcClient
from conflux.utils import encode_hex, privtoaddr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3
from easysolc import Solc

class CommissionPrivilegeTest(ConfluxTestFramework):
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
        receipts = [client.get_transaction_receipt(tx.hash_hex()) for tx in all_txs]
        self.log.debug("Receipts received: {}".format(receipts))
        if check_status:
            map(lambda x: assert_equal(x['outcomeStatus'], 0), receipts)
        return receipts

    def call_contract_function(self, contract, name, args, sender_key, value=None,
                               contract_addr=None, wait=False,
                               check_status=False,
                               storage_limit=None,
                               gas=None):
        if contract_addr:
            func = getattr(contract.functions, name)
        else:
            func = getattr(contract, name)
        attrs = {
            'nonce': self.get_nonce(encode_hex(privtoaddr(sender_key))),
            ** CommissionPrivilegeTest.REQUEST_BASE
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
        if storage_limit is not None:
            tx_data['storage_limit'] = storage_limit
        if gas is not None:
            tx_data['gas'] = gas
        transaction = create_transaction(**tx_data)
        self.send_transaction(transaction, wait, check_status)
        return transaction

    def run_test(self):
        # Prevent easysolc from configuring the root logger to print to stderr
        self.log.propagate = False
        sponsor_whitelist_contract_addr = Web3.toChecksumAddress("8ad036480160591706c831f0da19d1a424e39469")
        collateral_per_storage_key = 10 ** 18 // 16
        upper_bound = 5 * 10 ** 7

        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))

        control_contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/commission_privilege_control_abi.json"),
            bytecode_file = os.path.join(file_dir, "contracts/commission_privilege_control_bytecode.dat"),
        )

        test_contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/commission_privilege_test_abi.json"),
            bytecode_file = os.path.join(file_dir, "contracts/commission_privilege_test_bytecode.dat"),
        )

        start_p2p_connection(self.nodes)

        self.log.info("Initializing contract")
        genesis_key = self.genesis_priv_key
        genesis_addr = encode_hex(self.genesis_addr)
        self.log.info("genesis_addr={}".format(genesis_addr))
        nonce = 0
        gas_price = 1
        gas = 50000000
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
        (addr2, priv_key2) = client.rand_account()
        (addr3, priv_key3) = client.rand_account()
        tx = client.new_tx(
            sender=genesis_addr,
            priv_key=genesis_key,
            value=10 ** 18,
            nonce=self.get_nonce(genesis_addr),
            receiver=addr1)
        client.send_tx(tx, True)
        assert_equal(client.get_balance(addr1), 10 ** 18)
        tx = client.new_tx(
            sender=genesis_addr,
            priv_key=genesis_key,
            value=10 ** 18,
            nonce=self.get_nonce(genesis_addr),
            receiver=addr2)
        client.send_tx(tx, True)
        assert_equal(client.get_balance(addr2), 10 ** 18)
        tx = client.new_tx(
            sender=genesis_addr,
            priv_key=genesis_key,
            value=3 * 10 ** 18,
            nonce=self.get_nonce(genesis_addr),
            receiver=addr3)
        client.send_tx(tx, True)
        assert_equal(client.get_balance(addr3), 3 * 10 ** 18)

        # setup contract
        transaction = self.call_contract_function(
            contract=test_contract,
            name="constructor",
            args=[],
            sender_key=self.genesis_priv_key)
        contract_addr = self.wait_for_tx([transaction], True)[0]['contractCreated']
        self.log.info("contract_addr={}".format(contract_addr))
        assert_equal(client.get_balance(contract_addr), 0)

        # sponsor the contract failed due to sponsor_balance < 1000 * upper_bound
        b0 = client.get_balance(genesis_addr)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_gas",
            args=[Web3.toChecksumAddress(contract_addr), upper_bound],
            value=upper_bound * 1000 - 1,
            sender_key=self.genesis_priv_key,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 0)
        assert_equal(client.get_sponsor_for_gas(contract_addr), "0x0000000000000000000000000000000000000000")
        assert_equal(client.get_sponsor_gas_bound(contract_addr), 0)
        assert_equal(client.get_balance(genesis_addr), b0 - gas)

        # sponsor the contract succeed
        b0 = client.get_balance(genesis_addr)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_gas",
            args=[Web3.toChecksumAddress(contract_addr), upper_bound],
            value=10 ** 18,
            sender_key=self.genesis_priv_key,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr)
        assert_equal(client.get_sponsor_gas_bound(contract_addr), upper_bound)
        assert_equal(client.get_balance(genesis_addr), b0 - 10 ** 18 - gas)

        # set privilege for addr1
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        self.call_contract_function(
            contract=test_contract,
            name="add",
            args=[Web3.toChecksumAddress(addr1)],
            sender_key=genesis_key,
            contract_addr=contract_addr,
            wait=True,
            check_status=True)
        assert_equal(client.get_balance(genesis_addr), b0 - gas - collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + collateral_per_storage_key)

        # addr1 call contract with privilege
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        self.call_contract_function(
            contract=test_contract,
            name="foo",
            args=[],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            wait=True,
            check_status=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - gas)
        assert_equal(client.get_balance(addr1), b1)

        # addr1 call contract with privilege and large tx fee
        b1 = client.get_balance(addr1)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        self.call_contract_function(
            contract=test_contract,
            name="foo",
            args=[],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            wait=True,
            check_status=True,
            gas=upper_bound+ 1)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_balance(addr1), b1 - upper_bound - 1)

        # addr2 call contract without privilege
        b2 = client.get_balance(addr2)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        self.call_contract_function(
            contract=test_contract,
            name="foo",
            args=[],
            sender_key=priv_key2,
            contract_addr=contract_addr,
            wait=True,
            check_status=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_balance(addr2), b2 - gas)

        # set privilege for addr2
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        self.call_contract_function(
            contract=test_contract,
            name="add",
            args=[Web3.toChecksumAddress(addr2)],
            sender_key=genesis_key,
            contract_addr=contract_addr,
            wait=True,
            check_status=True)
        assert_equal(client.get_balance(genesis_addr), b0 - gas - collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + collateral_per_storage_key)

        # now, addr2 call contract with privilege
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        self.call_contract_function(
            contract=test_contract,
            name="foo",
            args=[],
            sender_key=priv_key2,
            contract_addr=contract_addr,
            wait=True,
            check_status=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - gas)
        assert_equal(client.get_balance(addr2), b2)

        # remove privilege for addr1
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        self.call_contract_function(
            contract=test_contract,
            name="remove",
            args=[Web3.toChecksumAddress(addr1)],
            sender_key=genesis_key,
            contract_addr=contract_addr,
            wait=True,
            check_status=True)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 - collateral_per_storage_key)
        assert_equal(client.get_balance(genesis_addr), b0 - gas + collateral_per_storage_key)

        # addr1 call contract without privilege
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        self.call_contract_function(
            contract=test_contract,
            name="foo",
            args=[],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            wait=True,
            check_status=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_balance(addr1), b1 - gas)

        # new sponsor failed due to small sponsor_balance
        b3 = client.get_balance(addr3)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_gas",
            args=[Web3.toChecksumAddress(contract_addr), upper_bound + 1],
            value=5 * 10 ** 17,
            sender_key=priv_key3,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr)
        assert_equal(client.get_balance(addr3), b3 - gas)

        # new sponsor failed due to small upper bound
        b3 = client.get_balance(addr3)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_gas",
            args=[Web3.toChecksumAddress(contract_addr), upper_bound],
            value=10 ** 18,
            sender_key=priv_key3,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr)
        assert_equal(client.get_balance(addr3), b3 - gas)

        # new sponsor succeed
        b0 = client.get_balance(genesis_addr)
        b3 = client.get_balance(addr3)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_gas",
            args=[Web3.toChecksumAddress(contract_addr), upper_bound + 1],
            value=10 ** 18,
            sender_key=priv_key3,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_gas_bound(contract_addr), upper_bound + 1)
        assert_equal(client.get_sponsor_for_gas(contract_addr), addr3)
        assert_equal(client.get_balance(addr3), b3 - 10 ** 18 - gas)
        assert_equal(client.get_balance(genesis_addr), b0 + sb)

        # sponsor the contract for collateral failed due to zero sponsor balance
        b3 = client.get_balance(addr3)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_collateral",
            args=[Web3.toChecksumAddress(contract_addr)],
            value=0,
            sender_key=priv_key3,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), 0)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), "0x0000000000000000000000000000000000000000")
        assert_equal(client.get_balance(addr3), b3 - gas)

        # sponsor the contract for collateral succeed
        b3 = client.get_balance(addr3)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_collateral",
            args=[Web3.toChecksumAddress(contract_addr)],
            value=10 ** 18 - 1,
            sender_key=priv_key3,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), 10 ** 18 - 1)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), addr3)
        assert_equal(client.get_balance(addr3), b3 - gas - 10 ** 18 + 1)

        # addr1 create 2 keys without privilege, and storage limit is 1, should failed
        b1 = client.get_balance(addr1)
        assert_equal(client.get_collateral_for_storage(contract_addr), 0)
        assert_equal(client.get_collateral_for_storage(addr1), 0)
        self.call_contract_function(
            contract=test_contract,
            name="par_add",
            args=[0, 2],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            wait=True,
            storage_limit=collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(contract_addr), 0)
        assert_equal(client.get_collateral_for_storage(addr1), 0)
        assert_equal(client.get_balance(addr1), b1 - gas)

        # addr1 create 2 keys without privilege, and storage limit is 2, should succeed
        b1 = client.get_balance(addr1)
        self.call_contract_function(
            contract=test_contract,
            name="par_add",
            args=[0, 2],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            wait=True,
            storage_limit=collateral_per_storage_key * 2)
        assert_equal(client.get_collateral_for_storage(contract_addr), 0)
        assert_equal(client.get_collateral_for_storage(addr1), collateral_per_storage_key * 2)
        assert_equal(client.get_balance(addr1), b1 - gas - collateral_per_storage_key * 2)

        # remove 1 key create by addr1
        b1 = client.get_balance(addr1)
        self.call_contract_function(
            contract=test_contract,
            name="par_del",
            args=[0, 1],
            sender_key=priv_key1,
            contract_addr=contract_addr,
            wait=True,
            storage_limit=collateral_per_storage_key * 2)
        assert_equal(client.get_collateral_for_storage(contract_addr), 0)
        assert_equal(client.get_collateral_for_storage(addr1), collateral_per_storage_key)
        assert_equal(client.get_balance(addr1), b1 - gas + collateral_per_storage_key)

        # addr2 create 2 keys with privilege, and storage limit is 1, should succeed
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        self.call_contract_function(
            contract=test_contract,
            name="par_add",
            args=[2, 4],
            sender_key=priv_key2,
            contract_addr=contract_addr,
            wait=True,
            storage_limit=collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 2)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc - collateral_per_storage_key * 2)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - gas)
        assert_equal(client.get_collateral_for_storage(addr2), 0)
        assert_equal(client.get_balance(addr2), b2)

        # addr2 create 13 keys with privilege, and storage limit is 0, should succeed
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        self.call_contract_function(
            contract=test_contract,
            name="par_add",
            args=[4, 17],
            sender_key=priv_key2,
            contract_addr=contract_addr,
            wait=True,
            storage_limit=0)
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 15)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc - collateral_per_storage_key * 13)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - gas)
        assert_equal(client.get_collateral_for_storage(addr2), 0)
        assert_equal(client.get_balance(addr2), b2)

        # now sponsor_balance is unable to pay collateral for storage
        # the balance of addr2 is able to pay 15 collateral for storage, but not 16
        assert_greater_than(collateral_per_storage_key, client.get_sponsor_balance_for_collateral(contract_addr))
        assert_greater_than(collateral_per_storage_key * 16, client.get_balance(addr2))
        assert_greater_than(client.get_balance(addr2), collateral_per_storage_key * 15)

        # addr2 create 1 keys with privilege, and storage limit is 0, should failed
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        self.call_contract_function(
            contract=test_contract,
            name="par_add",
            args=[17, 18],
            sender_key=priv_key2,
            contract_addr=contract_addr,
            wait=True,
            storage_limit=0)
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 15)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - gas)
        assert_equal(client.get_collateral_for_storage(addr2), 0)
        assert_equal(client.get_balance(addr2), b2)

        # addr2 create 1 keys with privilege, and storage limit is 2, should succeed
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        self.call_contract_function(
            contract=test_contract,
            name="par_add",
            args=[17, 18],
            sender_key=priv_key2,
            contract_addr=contract_addr,
            wait=True,
            storage_limit=collateral_per_storage_key * 2)
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 15)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - gas)
        assert_equal(client.get_collateral_for_storage(addr2), collateral_per_storage_key)
        assert_equal(client.get_balance(addr2), b2 - collateral_per_storage_key)

        # addr2 del 10 keys with privilege
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        self.call_contract_function(
            contract=test_contract,
            name="par_del",
            args=[2, 12],
            sender_key=priv_key2,
            contract_addr=contract_addr,
            wait=True,
            storage_limit=collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 5)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc + collateral_per_storage_key * 10)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - gas)
        assert_equal(client.get_collateral_for_storage(addr2), collateral_per_storage_key)
        assert_equal(client.get_balance(addr2), b2)

        # addr3 sponsor more, treat as transfer
        b3 = client.get_balance(addr3)
        sb = client.get_sponsor_balance_for_collateral(contract_addr)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_collateral",
            args=[Web3.toChecksumAddress(contract_addr)],
            value=sb,
            sender_key=priv_key3,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sb * 2)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), addr3)
        assert_equal(client.get_balance(addr3), b3 - gas - sb)

        # genesis sponsor with sponsor balance, should failed
        b0 = client.get_balance(genesis_addr)
        sb = client.get_sponsor_balance_for_collateral(contract_addr)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_collateral",
            args=[Web3.toChecksumAddress(contract_addr)],
            value=sb + 1,
            sender_key=self.genesis_priv_key,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sb)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), addr3)
        assert_equal(client.get_balance(genesis_addr), b0 - gas)

        # genesis sponsor with sponsor balance and collateral_for_storage, should succeed
        b0 = client.get_balance(genesis_addr)
        b3 = client.get_balance(addr3)
        cfs = client.get_collateral_for_storage(contract_addr)
        sb = client.get_sponsor_balance_for_collateral(contract_addr)
        self.call_contract_function(
            contract=control_contract,
            name="set_sponsor_for_collateral",
            args=[Web3.toChecksumAddress(contract_addr)],
            value=sb + cfs + 1,
            sender_key=self.genesis_priv_key,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True)
        assert_equal(client.get_collateral_for_storage(contract_addr), cfs)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sb + cfs + 1)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), genesis_addr)
        assert_equal(client.get_balance(genesis_addr), b0 - gas - sb - cfs - 1)
        assert_equal(client.get_balance(addr3), b3 + sb + cfs)

        self.log.info("Pass")


if __name__ == "__main__":
    CommissionPrivilegeTest().main()
