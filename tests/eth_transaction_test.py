#!/usr/bin/env python3
from eth_utils import decode_hex
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS
from conflux.utils import priv_to_addr
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3

CFX = 10 ** 18
GDrip = 10 ** 9


class EthTransactionTest(ConfluxTestFramework):
    REQUEST_BASE = {
        'gas': CONTRACT_DEFAULT_GAS,
        'gasPrice': 1,
        'chainId': 1,
    }
    ETH_KEY = "0x6195034b293444a42eb382550ab5649f3a094fb3e57c32d8597bbfc63f85abc8"

    def __init__(self):
        super().__init__()

        self.nonce_map = {}
        self.genesis_priv_key = default_config['GENESIS_PRI_KEY']
        self.genesis_addr = priv_to_addr(self.genesis_priv_key)
        self.eth_priv_key = EthTransactionTest.ETH_KEY
        self.eth_addr = priv_to_addr(self.eth_priv_key)
        self.eth_hex_addr = encode_hex_0x(self.eth_addr)

    def set_test_params(self):
        self.num_nodes = 2

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

    def call_contract_function(self, contract, name, args, sender_key, eth_tx=False, value=None,
                               contract_addr=None, wait=False,
                               check_status=False,
                               storage_limit=None):
        if contract_addr:
            func = getattr(contract.functions, name)
        else:
            func = getattr(contract, name)
        attrs = {
            'nonce': self.get_nonce(priv_to_addr(sender_key)),
            **EthTransactionTest.REQUEST_BASE
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
        if eth_tx:
            tx_data['storage_limit'] = 0xffff_ffff_ffff_ffff
            tx_data['epoch_height'] = 0xffff_ffff_ffff_ffff
        if storage_limit:
            tx_data['storage_limit'] = storage_limit
        transaction = create_transaction(**tx_data)
        self.send_transaction(transaction, wait, check_status)
        return transaction

    def run_test(self):
        file_dir = os.path.dirname(os.path.realpath(__file__))

        storage_contract = get_contract_instance(
            abi_file=os.path.join(file_dir, "contracts/simple_storage.abi"),
            bytecode_file=os.path.join(file_dir, "contracts/simple_storage.dat"),
        )

        start_p2p_connection(self.nodes)

        self.log.info("Initializing contract")
        genesis_addr = self.genesis_addr
        self.log.info("genesis_addr={}".format(encode_hex_0x(genesis_addr)))

        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        client = RpcClient(self.nodes[0])
        client1 = RpcClient(self.nodes[1])

        tx = client.new_tx(value=int(0.625 * CFX) + GDrip, receiver=self.eth_hex_addr,
                           nonce=self.get_nonce(genesis_addr))
        client.send_tx(tx, True)
        assert_equal(client.get_balance(self.eth_hex_addr), int(0.625 * CFX) + GDrip)

        # deploy pay contract
        block_gen_thread.stop()  # stop the block generation to test transaction relay.
        time.sleep(3)
        self.log.info("Deploying contract")
        tx = self.call_contract_function(
            contract=storage_contract,
            name="constructor",
            args=[],
            sender_key=self.eth_priv_key,
            eth_tx=True,
        )
        assert_equal(tx["epoch_height"], 0xffff_ffff_ffff_ffff)
        wait_until(lambda: self.nodes[1].tx_inspect(tx.hash_hex())['exist'], timeout=5)
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        receipt = self.wait_for_tx([tx], True)[0]
        assert_equal(int(receipt["storageCollateralized"], 0), 640)

        contract_addr = receipt['contractCreated']
        self.log.info("contract_addr={}".format(contract_addr))
        assert_equal(client.get_collateral_for_storage(self.eth_hex_addr), int(0.625 * CFX))
        assert_greater_than(GDrip, client.get_balance(self.eth_hex_addr))

        storage_contract = get_contract_instance(
            abi_file=os.path.join(file_dir, "contracts/simple_storage.abi"),
            bytecode_file=os.path.join(file_dir, "contracts/simple_storage.dat"),
        )

        # Should fail because of not enough balance for storage.
        self.log.info("Sending transaction without enough collateral")
        tx = self.call_contract_function(
            contract=storage_contract,
            contract_addr=contract_addr,
            name="setFresh",
            args=[],
            sender_key=self.eth_priv_key,
            eth_tx=True,
        )
        receipt = self.wait_for_tx([tx])[0]
        assert_equal(int(receipt["outcomeStatus"], 0), 1)

        sponsor_whitelist_contract_addr = Web3.toChecksumAddress("0888000000000000000000000000000000000001")
        file_dir = os.path.dirname(os.path.realpath(__file__))
        control_contract_file_path = os.path.join(file_dir, "..", "internal_contract", "metadata",
                                                  "SponsorWhitelistControl.json")
        control_contract_dict = json.loads(open(control_contract_file_path, "r").read())
        control_contract = get_contract_instance(contract_dict=control_contract_dict)
        self.log.info("Setting sponsor for collateral")
        self.call_contract_function(
            contract=control_contract,
            name="setSponsorForCollateral",
            args=[Web3.toChecksumAddress(contract_addr)],
            value=1 * CFX,
            sender_key=self.genesis_priv_key,
            contract_addr=sponsor_whitelist_contract_addr,
            wait=True,
            check_status=True)
        self.log.info("Sending balance to eth_like tx")
        tx = client.new_tx(value=int(0.0625 * CFX), receiver=self.eth_hex_addr,
                           nonce=self.get_nonce(genesis_addr))
        client.send_tx(tx, True)
        self.log.info("Setting whitelist for all")
        self.call_contract_function(
            contract=control_contract,
            name="addPrivilegeByAdmin",
            args=[Web3.toChecksumAddress(contract_addr), [Web3.toChecksumAddress("0x" + "0" * 40)]],
            sender_key=self.eth_priv_key,
            contract_addr=sponsor_whitelist_contract_addr,
            eth_tx=True,
            wait=True,
            check_status=True)

        # Should not fail because of sponsored
        self.log.info("Sending transaction when sponsored")
        time.sleep(3)
        block_gen_thread.stop()  # stop the block generation to test transaction relay in sponsorship

        tx = self.call_contract_function(
            contract=storage_contract,
            contract_addr=contract_addr,
            name="setFresh",
            args=[],
            sender_key=self.eth_priv_key,
            eth_tx=True,
        )

        wait_until(lambda: self.nodes[1].tx_inspect(tx.hash_hex())['exist'], timeout=5)
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        receipt = self.wait_for_tx([tx])[0]
        assert_equal(receipt["storageCoveredBySponsor"], True)
        assert_equal(int(receipt["storageCollateralized"], 0), 64)

        wait_until(lambda: checktx(self.nodes[1], tx.hash_hex()), timeout=20)

        self.log.info("Pass")


if __name__ == "__main__":
    EthTransactionTest().main()
