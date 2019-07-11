#!/usr/bin/env python3
import datetime
from http.client import CannotSendRequest
from conflux.utils import convert_to_nodeid, privtoaddr, parse_as_int, encode_hex
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import  create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
import pickle


class SingleBench(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        # self.setup_nodes(binary=[os.path.join(
        #     os.path.dirname(os.path.realpath(__file__)),
        #     "../target/release/conflux")])
        self.setup_nodes()

    def run_test(self):
        # Start mininode connection
        self.node = self.nodes[0]
        start_p2p_connection([self.node])

        block_gen_thread = BlockGenThread([self.node], self.log, num_txs=100, interval_fixed=0.2)
        block_gen_thread.start()
        tx_n = 100000

        generate = False
        if generate:
            f = open("encoded_tx", "wb")
            '''Test Random Transactions'''
            genesis_key = default_config["GENESIS_PRI_KEY"]
            balance_map = {genesis_key: default_config["TOTAL_COIN"]}
            nonce_map = {genesis_key: 0}
            all_txs = []
            gas_price = 1
            self.log.info("start to generate %d transactions", tx_n)
            for i in range(tx_n):
                if i % 1000 == 0:
                    self.log.debug("generated %d tx", i)
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
                self.log.debug("%s send %d to %s nonce=%d balance: sender=%s, receiver=%s", encode_hex(privtoaddr(sender_key)), value, encode_hex(privtoaddr(receiver_sk)), nonce, balance_map[sender_key], balance_map[receiver_sk])
                all_txs.append(tx)
                nonce_map[sender_key] = nonce + 1
                balance_map[sender_key] -= value + gas_price * 21000
            encoded_txs = []
            batch_tx = []
            i = 0
            for tx in all_txs:
                batch_tx.append(tx)
                i += 1
                if i  % 1000 == 0:
                    encoded = rlp.encode(Transactions(transactions=batch_tx))
                    encoded_txs.append(encoded)
                    batch_tx = []
            pickle.dump(encoded_txs, f)
            pickle.dump(balance_map, f)
        else:
            f = open("encoded_tx", "rb")
            encoded_txs = pickle.load(f)
            balance_map = pickle.load(f)

        f.close()
        start_time = datetime.datetime.now()
        for encoded in encoded_txs:
            self.node.p2p.send_protocol_packet(int_to_bytes(
                TRANSACTIONS) + encoded)
        for k in balance_map:
                wait_until(lambda: self.check_account(k, balance_map))
        end_time = datetime.datetime.now()
        time_used = (end_time - start_time).total_seconds()
        block_gen_thread.stop()
        block_gen_thread.join()
        self.log.info("Time used: %f seconds", time_used)
        self.log.info("Tx per second: %f", tx_n / time_used)

    def check_account(self, k, balance_map):
        addr = eth_utils.encode_hex(privtoaddr(k))
        try:
            balance = parse_as_int(self.node.cfx_getBalance(addr))
        except Exception as e:
            self.log.info("Fail to get balance, error=%s", str(e))
            time.sleep(0.1)
            return False
        if balance == balance_map[k]:
            return True
        else:
            self.log.info("Remote balance:%d, local balance:%d", balance, balance_map[k])
            time.sleep(1)
            return False


if __name__ == "__main__":
    SingleBench().main()
