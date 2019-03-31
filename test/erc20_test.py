#!/usr/bin/env python3
from http.client import CannotSendRequest
from eth_utils import decode_hex
from conflux.utils import encode_hex, privtoaddr, parse_as_int
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3
from easysolc import Solc

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 8

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        # Prevent easysolc from configuring the root logger to print to stderr
        self.log.propagate = False

        solc = Solc()
        erc20_contract = solc.get_contract_instance(source=os.path.dirname(os.path.realpath(__file__)) + "/erc20.sol", contract_name="FixedSupplyToken")

        start_p2p_connection(self.nodes)

        self.log.info("Initializing contract")
        genesis_key = default_config["GENESIS_PRI_KEY"]
        genesis_addr = privtoaddr(genesis_key)
        nonce = 0
        gas_price = 1
        gas = 50000000
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()
        self.tx_conf = {"from":Web3.toChecksumAddress(encode_hex_0x(genesis_addr)), "nonce":int_to_hex(nonce), "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price)}
        raw_create = erc20_contract.constructor().buildTransaction(self.tx_conf)
        tx_data = decode_hex(raw_create["data"])
        tx_create = create_transaction(pri_key=genesis_key, receiver=b'', nonce=nonce, gas_price=gas_price, data=tx_data, gas=gas, value=0)
        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[tx_create]))
        self.wait_for_tx([tx_create])
        self.log.info("Contract created, start transfering tokens")

        tx_n = 10
        self.tx_conf["to"] = Web3.toChecksumAddress(encode_hex_0x(sha3_256(rlp.encode([genesis_addr, nonce]))[-20:]))
        nonce += 1
        balance_map = {genesis_key: 1000000 * 10**18}
        sender_key = genesis_key
        all_txs = []
        for i in range(tx_n):
            value = int((balance_map[sender_key] - ((tx_n - i) * 21000 * gas_price)) * random.random())
            receiver_sk, _ = ec_random_keys()
            balance_map[receiver_sk] = value
            tx_data = decode_hex(erc20_contract.functions.transfer(Web3.toChecksumAddress(encode_hex(privtoaddr(receiver_sk))), value).buildTransaction(self.tx_conf)["data"])
            tx = create_transaction(pri_key=sender_key, receiver=decode_hex(self.tx_conf["to"]), value=0, nonce=nonce, gas=gas,
                                    gas_price=gas_price, data=tx_data)
            r = random.randint(0, self.num_nodes - 1)
            self.nodes[r].p2p.send_protocol_msg(Transactions(transactions=[tx]))
            nonce += 1
            balance_map[sender_key] -= value
            all_txs.append(tx)
        self.log.info("Wait for transactions to be executed")
        self.wait_for_tx(all_txs)
        self.log.info("Check final token balance")
        for sk in balance_map:
            addr = privtoaddr(sk)
            assert_equal(self.get_balance(erc20_contract, addr, nonce), balance_map[sk])
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

    def get_balance(self, contract, token_address, nonce):
        tx = contract.functions.balanceOf(Web3.toChecksumAddress(encode_hex(token_address))).buildTransaction(self.tx_conf)
        tx["value"] = int_to_hex(tx['value'])
        tx["hash"] = "0x"+"0"*64
        tx["nonce"] = int_to_hex(nonce)
        tx["v"] = "0x0"
        tx["r"] = "0x0"
        tx["s"] = "0x0"
        balance = bytes_to_int(bytes(self.nodes[0].cfx_call(tx)))
        self.log.debug("address=%s, balance=%s", encode_hex(token_address), balance)
        return balance


if __name__ == "__main__":
    P2PTest().main()
