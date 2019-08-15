#!/usr/bin/env python3

from conflux.utils import convert_to_nodeid, privtoaddr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import  create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *


class MessageTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 0
        self.conf_parameters = {"log_level":"\"error\""}

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):

        # Start mininode connection
        default_node = DefaultNode()
        self.node = default_node
        kwargs = {}
        args = {}
        kwargs['dstport'] = 32323
        kwargs['dstaddr'] = '127.0.0.1'
        default_node.peer_connect(*args, **kwargs)
        network_thread_start()
        default_node.wait_for_status()

        # Start rpc connection
        self.rpc = get_simple_rpc_proxy(
            "http://127.0.0.1:11000",
            1)
        challenge = random.randint(0, 2**32-1)
        signature = self.rpc.getnodeid(list(int_to_bytes(challenge)))
        node_id, x, y = convert_to_nodeid(signature, challenge)
        self.log.info("get nodeid %s", eth_utils.encode_hex(node_id))

        block_gen_thread = BlockGenThread([self.rpc], self.log, num_txs = 100, interval_fixed=0.2)
        block_gen_thread.start()
        genesis_key = default_config["GENESIS_PRI_KEY"]
        balance_map = {genesis_key: default_config["TOTAL_COIN"]}
        self.log.info("Initial State: (sk:%d, addr:%s, balance:%d)", bytes_to_int(genesis_key),
                      eth_utils.encode_hex(privtoaddr(genesis_key)), balance_map[genesis_key])
        nonce_map = {genesis_key: 0}
        '''Test Random Transactions'''
        all_txs = []
        tx_n = 10000
        gas_price = 1
        self.log.info("start to generate %d transactions with about %d seconds", tx_n, tx_n/10/2)
        for i in range(tx_n):
            if i % 1000 == 0:
                self.log.info("generated %d tx", i)
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
            all_txs.append(tx)
            nonce_map[sender_key] = nonce + 1
            balance_map[sender_key] -= value + gas_price * 21000
        i = 0
        for tx in all_txs:
            i += 1
            if i % 1000 == 0:
                self.log.info("Sent %d tx", i)
            self.node.send_protocol_msg(Transactions(transactions=[tx]))
        for k in balance_map:
            wait_until(lambda: self.check_account(k, balance_map))
        block_gen_thread.stop()
        block_gen_thread.join()
        self.log.info("Pass")
        while True:
            pass

    def send_msg(self, msg):
        self.node.send_protocol_msg(msg)

    def check_account(self, k, balance_map):
        addr = eth_utils.encode_hex(privtoaddr(k))
        try:
            balance = parse_as_int(self.rpc.cfx_getBalance(addr))
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
    MessageTest().main()
