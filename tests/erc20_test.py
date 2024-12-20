#!/usr/bin/env python3
from eth_utils import decode_hex
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS
from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 8

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        file_dir = os.path.dirname(os.path.realpath(__file__))
        erc20_contract = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/erc20_abi.json"),
            bytecode_file = os.path.join(file_dir, "contracts/erc20_bytecode.dat"),
        )

        gas_price = 1
        gas = CONTRACT_DEFAULT_GAS

        start_p2p_connection(self.nodes)

        self.log.info("Initializing contract")
        genesis_key = default_config["GENESIS_PRI_KEY"]
        genesis_addr = encode_hex_0x(priv_to_addr(genesis_key))
        nonce = 0
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()
        self.tx_conf = {"from":Web3.to_checksum_address(genesis_addr), "nonce":int_to_hex(nonce), "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        raw_create = erc20_contract.constructor().build_transaction(self.tx_conf)
        tx_data = decode_hex(raw_create["data"])
        tx_create = create_transaction(pri_key=genesis_key, receiver=b'', nonce=nonce, gas_price=gas_price, data=tx_data, gas=gas, value=0, storage_limit=1920)
        c0 = self.client.get_collateral_for_storage(genesis_addr)
        self.client.send_tx(tx_create, True)
        receipt = self.client.get_transaction_receipt(tx_create.hash_hex())
        c1 = self.client.get_collateral_for_storage(genesis_addr)
        assert_equal(c1 - c0, 1920 * 10 ** 18 / 1024)
        contract_addr = receipt['contractCreated']
        self.log.info("Contract " + str(contract_addr) + " created, start transferring tokens")

        tx_n = 10
        self.tx_conf["to"] = contract_addr
        nonce += 1
        balance_map = {genesis_key: 1000000 * 10**18}
        sender_key = genesis_key
        all_txs = []
        for i in range(tx_n):
            value = int((balance_map[sender_key] - ((tx_n - i) * 21000 * gas_price)) * random.random())
            receiver_sk, _ = ec_random_keys()
            balance_map[receiver_sk] = value
            tx_data = decode_hex(erc20_contract.functions.transfer(Web3.to_checksum_address(encode_hex(priv_to_addr(receiver_sk))), value).build_transaction(self.tx_conf)["data"])
            tx = create_transaction(pri_key=sender_key, receiver=decode_hex(self.tx_conf["to"]), value=0, nonce=nonce, gas=gas,
                                    gas_price=gas_price, data=tx_data, storage_limit=64)
            r = random.randint(0, self.num_nodes - 1)
            self.nodes[r].p2p.send_protocol_msg(Transactions(transactions=[tx]))
            nonce += 1
            balance_map[sender_key] -= value
            all_txs.append(tx)
        self.log.info("Wait for transactions to be executed")
        self.wait_for_tx(all_txs)
        self.log.info("Check final token balance")
        for sk in balance_map:
            addr = priv_to_addr(sk)
            assert_equal(self.get_balance(erc20_contract, addr), balance_map[sk])
        c2 = self.client.get_collateral_for_storage(genesis_addr)
        assert_equal(c2 - c1, 64 * tx_n * 10 ** 18 / 1024)
        block_gen_thread.stop()
        block_gen_thread.join()
        sync_blocks(self.nodes)
        self.log.info("Pass")

    def get_balance(self, contract, token_address):
        tx = contract.functions.balanceOf(Web3.to_checksum_address(encode_hex(token_address))).build_transaction(self.tx_conf)
        result = self.client.call(tx["to"], tx["data"])
        balance = bytes_to_int(decode_hex(result))
        self.log.debug("address=%s, balance=%s", encode_hex(token_address), balance)
        return balance


if __name__ == "__main__":
    P2PTest().main()
