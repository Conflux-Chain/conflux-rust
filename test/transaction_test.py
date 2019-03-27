#!/usr/bin/env python3
from http.client import CannotSendRequest

from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt

from conflux import utils
from conflux.utils import encode_hex, bytes_to_int, privtoaddr, parse_as_int
from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class P2PTest(DefaultConfluxTestFramework):
    def run_test(self):
        genesis_key = default_config["GENESIS_PRI_KEY"]
        balance_map = {genesis_key: default_config["TOTAL_COIN"]}
        self.log.info("Initial State: (sk:%d, addr:%s, balance:%d)", bytes_to_int(genesis_key),
                      eth_utils.encode_hex(privtoaddr(genesis_key)), balance_map[genesis_key])
        nonce_map = {genesis_key: 0}

        '''Check if transaction from uncommitted new address can be accepted'''
        tx_n = 5
        receiver_sk = genesis_key
        gas_price = 1
        for i in range(tx_n):
            sender_key = receiver_sk
            value = int((balance_map[sender_key] - ((tx_n - i) * 21000 * gas_price)) * random.random())
            nonce = nonce_map[sender_key]
            receiver_sk, _ = ec_random_keys()
            nonce_map[receiver_sk] = 0
            balance_map[receiver_sk] = value
            tx = create_transaction(pri_key=sender_key, receiver=privtoaddr(receiver_sk), value=value, nonce=nonce,
                                    gas_price=gas_price)
            r = random.randint(0, self.num_nodes - 1)
            self.nodes[r].p2p.send_protocol_msg(Transactions(transactions=[tx]))
            nonce_map[sender_key] = nonce + 1
            balance_map[sender_key] -= value + gas_price * 21000
            self.log.debug("New tx %s: %s send value %d to %s, sender balance:%d, receiver balance:%d", encode_hex(tx.hash), eth_utils.encode_hex(privtoaddr(sender_key))[-4:],
                           value, eth_utils.encode_hex(privtoaddr(receiver_sk))[-4:], balance_map[sender_key], balance_map[receiver_sk])
            self.log.debug("Send Transaction %s to node %d", encode_hex(tx.hash), r)
            time.sleep(random.random() / 100)
        block_gen_thread = BlockGenThread(self.nodes, self.log, interval_base=0.2)
        block_gen_thread.start()
        for k in balance_map:
            self.log.info("Check account sk:%s addr:%s", bytes_to_int(k), eth_utils.encode_hex(privtoaddr(k)))
            wait_until(lambda: self.check_account(k, balance_map))
        self.log.info("Pass 1")

        '''Test Random Transactions'''
        all_txs = []
        tx_n = 1000
        self.log.info("start to generate %d transactions with about %d seconds", tx_n, tx_n/100/2)
        for i in range(tx_n):
            sender_key = random.choice(list(balance_map))
            nonce = nonce_map[sender_key]
            if random.random() < 0.1 and balance_map[sender_key] > 21000 * 4 * tx_n:
                value = int(balance_map[sender_key] * 0.5)
                receiver_sk, _ = ec_random_keys()
                nonce_map[receiver_sk] = 0
                balance_map[receiver_sk] = value
            else:
                value = 1
                receiver_sk = random.choice(list(balance_map))
                balance_map[receiver_sk] += value
            # not enough transaction fee (gas_price * gas_limit) should not happen for now
            assert balance_map[sender_key] >= value + gas_price * 21000
            tx = create_transaction(pri_key=sender_key, receiver=privtoaddr(receiver_sk), value=value, nonce=nonce,
                                    gas_price=gas_price)
            r = random.randint(0, self.num_nodes - 1)
            self.nodes[r].p2p.send_protocol_msg(Transactions(transactions=[tx]))
            all_txs.append(tx)
            nonce_map[sender_key] = nonce + 1
            balance_map[sender_key] -= value + gas_price * 21000
            self.log.debug("New tx %s: %s send value %d to %s, sender balance:%d, receiver balance:%d nonce:%d", encode_hex(tx.hash), eth_utils.encode_hex(privtoaddr(sender_key))[-4:],
                          value, eth_utils.encode_hex(privtoaddr(receiver_sk))[-4:], balance_map[sender_key], balance_map[receiver_sk], nonce)
            self.log.debug("Send Transaction %s to node %d", encode_hex(tx.hash), r)
            time.sleep(random.random() / 100)
        for k in balance_map:
            self.log.info("Account %s with balance:%s", bytes_to_int(k), balance_map[k])
        for tx in all_txs:
            self.log.debug("Wait for tx to confirm %s", tx.hash_hex())
            for i in range(3):
                try:
                    retry = True
                    while retry:
                        try:
                            wait_until(lambda: checktx(self.nodes[0], tx.hash_hex()), timeout=120)
                            retry = False
                        except CannotSendRequest:
                            time.sleep(0.01)
                    break
                except AssertionError as _:
                    self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[tx]))
                if i == 2:
                    raise AssertionError("Tx {} not confirmed after 30 seconds".format(tx.hash_hex()))

        for k in balance_map:
            self.log.info("Check account sk:%s addr:%s", bytes_to_int(k), eth_utils.encode_hex(privtoaddr(k)))
            wait_until(lambda: self.check_account(k, balance_map))
        block_gen_thread.stop()
        block_gen_thread.join()
        sync_blocks(self.nodes)
        self.log.info("Pass")

    def check_account(self, k, balance_map):
        addr = eth_utils.encode_hex(privtoaddr(k))
        try:
            balance = parse_as_int(self.nodes[0].cfx_getBalance(addr))
        except Exception as e:
            self.log.info("Fail to get balance, error=%s", str(e))
            return False
        if balance == balance_map[k]:
            return True
        else:
            self.log.info("Remote balance:%d, local balance:%d", balance, balance_map[k])
            time.sleep(1)
            return False


if __name__ == "__main__":
    P2PTest().main()
