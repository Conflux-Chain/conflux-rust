#!/usr/bin/env python3
from http.client import CannotSendRequest
from conflux.transactions import CONTRACT_DEFAULT_GAS, charged_of_huge_gas
from conflux.utils import encode_hex, bytes_to_int, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_block, create_transaction, wait_for_initial_nonce_for_privkey, wait_for_account_stable
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class TransactionTest(DefaultConfluxTestFramework):
    def run_test(self):
        genesis_key = default_config["GENESIS_PRI_KEY"]
        balance_map = {genesis_key: default_config["TOTAL_COIN"]}
        self.log.info("Initial State: (sk:%d, addr:%s, balance:%d)", bytes_to_int(genesis_key),
                      eth_utils.encode_hex(priv_to_addr(genesis_key)), balance_map[genesis_key])
        nonce_map = {genesis_key: 0}
        block_gen_thread = BlockGenThread(self.nodes, self.log, interval_base=0.2)
        block_gen_thread.start()

        '''Check if transaction from uncommitted new address can be accepted'''
        tx_n = 5
        new_keys = set()
        gas_price = 1
        for i in range(tx_n):
            sender_key = genesis_key
            receiver_sk, _ = ec_random_keys()
            new_keys.add(receiver_sk)
            value = int((balance_map[sender_key] - ((tx_n - i) * 21000 * gas_price)) * random.random())
            balance_map[receiver_sk] = value
            nonce = nonce_map[sender_key]
            receiver_addr = priv_to_addr(receiver_sk)
            tx = create_transaction(pri_key=sender_key, receiver=receiver_addr, value=value, nonce=nonce,
                                    gas_price=gas_price)
            r = random.randint(0, self.num_nodes - 1)
            r = 0
            self.nodes[r].p2p.send_protocol_msg(Transactions(transactions=[tx]))
            nonce_map[sender_key] = nonce + 1
            balance_map[sender_key] -= value + gas_price * 21000
            self.log.debug("New tx %s: %s send value %d to %s, sender balance:%d, receiver balance:%d", encode_hex(tx.hash), eth_utils.encode_hex(priv_to_addr(sender_key))[-4:],
                           value, eth_utils.encode_hex(priv_to_addr(receiver_sk))[-4:], balance_map[sender_key], balance_map[receiver_sk])
            self.log.debug("Send Transaction %s to node %d", encode_hex(tx.hash), r)
        for k in balance_map:
            self.log.info("Check account sk:%s addr:%s", bytes_to_int(k), eth_utils.encode_hex(priv_to_addr(k)))
            wait_until(lambda: self.check_account(k, balance_map))
        self.log.info("Pass 1")

        '''Test Random Transactions'''
        wait_for_account_stable()
        for key in new_keys:
            nonce_map[key] = wait_for_initial_nonce_for_privkey(self.nodes[0], key)
        all_txs = []
        tx_n = 1000
        self.log.info("start to generate %d transactions with about %d seconds", tx_n, tx_n/100/2)
        for i in range(tx_n):
            sender_key = random.choice(list(balance_map))
            nonce = nonce_map[sender_key]
            data = b''
            rand_n = random.random()
            gas = 21000
            storage_limit = 0
            if rand_n > 0.9 and balance_map[sender_key] > 21000 * 4 * tx_n:
                value = 0
                receiver = b''
                data = bytes([96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 16, 87, 96, 0, 128, 253, 91, 80, 96, 5, 96, 0, 129, 144, 85, 80, 96, 230, 128, 97, 0, 39, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 96, 4, 54, 16, 96, 67, 87, 96, 0, 53, 124, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 4, 128, 99, 96, 254, 71, 177, 20, 96, 72, 87, 128, 99, 109, 76, 230, 60, 20, 96, 127, 87, 91, 96, 0, 128, 253, 91, 52, 128, 21, 96, 83, 87, 96, 0, 128, 253, 91, 80, 96, 125, 96, 4, 128, 54, 3, 96, 32, 129, 16, 21, 96, 104, 87, 96, 0, 128, 253, 91, 129, 1, 144, 128, 128, 53, 144, 96, 32, 1, 144, 146, 145, 144, 80, 80, 80, 96, 167, 86, 91, 0, 91, 52, 128, 21, 96, 138, 87, 96, 0, 128, 253, 91, 80, 96, 145, 96, 177, 86, 91, 96, 64, 81, 128, 130, 129, 82, 96, 32, 1, 145, 80, 80, 96, 64, 81, 128, 145, 3, 144, 243, 91, 128, 96, 0, 129, 144, 85, 80, 80, 86, 91, 96, 0, 128, 84, 144, 80, 144, 86, 254, 161, 101, 98, 122, 122, 114, 48, 88, 32, 181, 24, 13, 149, 253, 195, 129, 48, 40, 237, 71, 246, 44, 124, 223, 112, 139, 118, 192, 219, 9, 64, 67, 245, 51, 180, 42, 67, 13, 49, 62, 21, 0, 41])
                gas = CONTRACT_DEFAULT_GAS
                is_payment = False
                storage_limit = 200000
            else:
                value = 1
                receiver_sk = random.choice(list(balance_map))
                receiver = priv_to_addr(receiver_sk)
                balance_map[receiver_sk] += value
                is_payment = True
            # not enough transaction fee (gas_price * gas_limit) should not happen for now
            assert balance_map[sender_key] >= value + gas_price * 21000
            tx = create_transaction(pri_key=sender_key, receiver=receiver, value=value, nonce=nonce,
                                    gas_price=gas_price, data=data, gas=gas, storage_limit=storage_limit)
            r = random.randint(0, self.num_nodes - 1)
            r = 0
            self.nodes[r].p2p.send_protocol_msg(Transactions(transactions=[tx]))
            all_txs.append(tx)
            nonce_map[sender_key] = nonce + 1
            if is_payment:
                balance_map[sender_key] -= value + gas_price * gas
            else:
                balance_map[sender_key] -= value + gas_price * charged_of_huge_gas(gas)
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
            self.log.info("Check account sk:%s addr:%s", bytes_to_int(k), eth_utils.encode_hex(priv_to_addr(k)))
            wait_until(lambda: self.check_account(k, balance_map))
        block_gen_thread.stop()
        block_gen_thread.join()
        sync_blocks(self.nodes)
        self.log.info("Pass")

    def check_account(self, k, balance_map):
        addr = eth_utils.encode_hex(priv_to_addr(k))
        try:
            balance = parse_as_int(self.nodes[0].cfx_getBalance(addr))
            staking_balance = parse_as_int(self.nodes[0].cfx_getStakingBalance(addr))
            collateral_for_storage = parse_as_int(self.nodes[0].cfx_getCollateralForStorage(addr))
        except Exception as e:
            self.log.info("Fail to get balance, error=%s", str(e))
            return False
        if balance + staking_balance + collateral_for_storage == balance_map[k]:
            return True
        else:
            self.log.info("Remote balance:%d, local balance:%d", balance + staking_balance + collateral_for_storage, balance_map[k])
            time.sleep(1)
            return False


if __name__ == "__main__":
    TransactionTest().main()
