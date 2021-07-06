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

        self.conf_parameters["unnamed_21autumn_transition_number"] = 20
        self.conf_parameters["unnamed_21autumn_transition_height"] = 15

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

        BlockGenThread(self.nodes, self.log, interval_fixed=1).start()

        client = RpcClient(self.nodes[0])

        tx = client.new_tx(value=int(0.625 * CFX) + GDrip, receiver=self.eth_hex_addr,
                           nonce=self.get_nonce(genesis_addr))
        client.send_tx(tx, True)
        assert_equal(client.get_balance(self.eth_hex_addr), int(0.625 * CFX) + GDrip)

        # deploy contract
        self.log.info("Deploying contract")
        tx = self.call_contract_function(
            contract=storage_contract,
            name="constructor",
            args=[],
            sender_key=self.eth_priv_key,
            eth_tx=True,
        )

        wait_until(lambda: self.nodes[1].tx_inspect(tx.hash_hex())['exist'], timeout=5)
        wait_until(lambda: client.epoch_number() >= 20, timeout=30)
        wait_until(lambda: self.nodes[1].tx_inspect(tx.hash_hex())['packed'], timeout=5)

        receipt = self.wait_for_tx([tx])[0]
        assert_greater_than_or_equal(int(receipt['epochNumber'], 0), 20)

        self.log.info("All test done")


if __name__ == "__main__":
    EthTransactionTest().main()
