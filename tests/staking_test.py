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

class StakingTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        # Prevent easysolc from configuring the root logger to print to stderr
        self.log.propagate = False

        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))
        staking_contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/storage_interest_staking_abi.json"),
            bytecode_file = os.path.join(file_dir, "contracts/storage_interest_staking_bytecode.dat"),
        )

        start_p2p_connection(self.nodes)

        self.log.info("Initializing contract")
        genesis_key = default_config["GENESIS_PRI_KEY"]
        genesis_addr = privtoaddr(genesis_key)
        nonce = 0
        gas_price = 1
        gas = 50000000
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()
        self.tx_conf = {"from":Web3.toChecksumAddress(encode_hex_0x(genesis_addr)), "nonce":int_to_hex(nonce), "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}

        tx_n = 1
        self.tx_conf["to"] = Web3.toChecksumAddress("443c409373ffd5c0bec1dddb7bec830856757b65")
        sender_key = genesis_key
        all_txs = []
        for i in range(tx_n):
            value = int(954)
            tx_data = decode_hex(staking_contract.functions.stake(value).buildTransaction(self.tx_conf)["data"])
            tx = create_transaction(pri_key=sender_key, receiver=decode_hex(self.tx_conf["to"]), value=0, nonce=nonce, gas=gas, gas_price=gas_price, data=tx_data)
            self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[tx]))
            nonce += 1
            all_txs.append(tx)
        self.log.info("Wait for transactions to be executed")
        self.wait_for_tx(all_txs)
        block_gen_thread.stop()
        block_gen_thread.join()
        sync_blocks(self.nodes)
        self.log.info("Pass")

    def wait_for_tx(self, all_txs):
        for tx in all_txs:
            self.log.debug("Wait for tx to confirm %s", tx.hash_hex())
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

if __name__ == "__main__":
    StakingTest().main()
