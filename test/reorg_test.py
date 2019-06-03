#!/usr/bin/env python3
from http.client import CannotSendRequest
from conflux.utils import encode_hex, privtoaddr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 8
        self.n_shard = 2

    def setup_network(self):
        self.setup_nodes()
        assert self.num_nodes % self.n_shard == 0, "each shard should have the same size"
        shard_size = int(self.num_nodes / self.n_shard)
        for s in range(self.n_shard):
            for i in range(s * shard_size, (s + 1) * shard_size - 1):
                connect_nodes(self.nodes, i, i + 1)

    def run_test(self):
        start_p2p_connection(self.nodes)
        block_gen_thread = BlockGenThread(self.nodes, self.log, interval_base=0.2)
        block_gen_thread.start()
        genesis_key = default_config["GENESIS_PRI_KEY"]
        tx_n = 100
        gas_price = 1
        shard_size = int(self.num_nodes / self.n_shard)
        shard_balance = []

        for s in range(self.n_shard):
            ''' Send random transactions to this shard s '''
            shard_nodes = self.nodes[s * shard_size: (s + 1) * shard_size]
            receiver_sk, _ = ec_random_keys()
            value = default_config["TOTAL_COIN"] - 21000
            balance_map = {receiver_sk: value}
            nonce_map = {receiver_sk: 0}
            tx = create_transaction(pri_key=genesis_key, receiver=privtoaddr(receiver_sk), value=value, nonce=0,
                                    gas_price=gas_price)
            shard_nodes[0].p2p.send_protocol_msg(Transactions(transactions=[tx]))
            for i in range(tx_n):
                sender_key = random.choice(list(balance_map))
                nonce = nonce_map[sender_key]
                if random.random() < 0.2 and balance_map[sender_key] > 21000 * 4 * tx_n:
                    value = int(balance_map[sender_key] * 0.5)
                    receiver_sk, _ = ec_random_keys()
                    nonce_map[receiver_sk] = 0
                    balance_map[receiver_sk] = value
                else:
                    value = 1
                    receiver_sk = random.choice(list(balance_map))
                    balance_map[receiver_sk] += value
                tx = create_transaction(pri_key=sender_key, receiver=privtoaddr(receiver_sk), value=value, nonce=nonce,
                                        gas_price=gas_price)
                r = random.randint(0, shard_size - 1)
                shard_nodes[r].p2p.send_protocol_msg(Transactions(transactions=[tx]))
                nonce_map[sender_key] = nonce + 1
                balance_map[sender_key] -= value + gas_price * 21000
                self.log.info("New tx %s: %s send value %d to %s, sender balance:%d, receiver balance:%d", encode_hex(tx.hash), eth_utils.encode_hex(privtoaddr(sender_key))[-4:],
                               value, eth_utils.encode_hex(privtoaddr(receiver_sk))[-4:], balance_map[sender_key], balance_map[receiver_sk])
                self.log.debug("Send Transaction %s to node %d", encode_hex(tx.hash), r)
                time.sleep(random.random() / 10)
            for k in balance_map:
                self.log.info("Check account sk:%s addr:%s", bytes_to_int(k), eth_utils.encode_hex(privtoaddr(k)))
                wait_until(lambda: self.check_account(k, balance_map, shard_nodes[0]))
            shard_balance.append(balance_map)

        def epochCheck(node):
            r = node.cfx_epochNumber()
            return int(r, 0) > 110

        wait_until(lambda: epochCheck(self.nodes[0]))
        wait_until(lambda: epochCheck(self.nodes[int(self.num_nodes / self.n_shard)]))
        for s in range(self.n_shard):
            connect_nodes(self.nodes, s * shard_size - 1, s * shard_size)
        block_gen_thread.stop()
        block_gen_thread.join()
        sync_blocks(self.nodes)

        ''' Check if the balance state of every node matches '''
        success_shard = -1
        # use the state of node 0 to find the winning shard
        for s in range(self.n_shard):
            balance_map = shard_balance[s]
            unmatch = False
            for k in balance_map:
                if not self.check_account(k, balance_map, self.nodes[0]):
                    unmatch = True
                    self.log.info("Final balance does not match shard %s, check next", s)
                    break
            if unmatch:
                continue
            success_shard = s
            break
        assert success_shard != -1, "The final state of node 0 matches no shard state"
        self.log.info("Shard %s succeeds", success_shard)
        for i in range(1, self.num_nodes):
            balance_map = shard_balance[success_shard]
            for k in balance_map:
                if not self.check_account(k, balance_map, self.nodes[i]):
                    raise AssertionError("Final balance of node {} does not match node 0, sender={}".format(i, k))
        self.log.info("Pass")

    def check_account(self, k, balance_map, node):
        addr = eth_utils.encode_hex(privtoaddr(k))
        try:
            balance = parse_as_int(node.cfx_getBalance(addr))
        except Exception as e:
            self.log.debug("Fail to get balance, error=%s", str(e))
            return False
        if balance == balance_map[k]:
            return True
        else:
            self.log.info("Remote balance:%d, local balance:%d", balance, balance_map[k])
            time.sleep(1)
            return False


if __name__ == "__main__":
    P2PTest().main()
