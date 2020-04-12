#!/usr/bin/env python3
from eth_utils import decode_hex
import conflux.config

'''
This is the state root for pre-generated genesis accounts in `genesis_secrets.txt`.
'''
conflux.config.default_config["GENESIS_STATE_ROOT"] = decode_hex("0xf734ca849ef7307458f4a69d2d33e1f0f9b214ae66ca3f754e9376aedaf9a4a0")
from conflux.utils import convert_to_nodeid, priv_to_addr, parse_as_int, encode_hex
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, wait_for_initial_nonce_for_privkey, wait_for_account_stable
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
import pickle


class SingleBench(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.rpc_timewait = 600
        self.conf_parameters["tx_pool_size"] = "500000"
        self.conf_parameters["heartbeat_timeout_ms"] = "10000000000"
        self.conf_parameters["record_tx_index"] = "false"
        # The file can be downloaded from `https://s3-ap-southeast-1.amazonaws.com/conflux-test/genesis_secrets.txt`
        genesis_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "genesis_secrets.txt")
        self.conf_parameters["genesis_secrets"] = f"\"{genesis_file_path}\""


    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        # Start mininode connection
        self.node = self.nodes[0]
        start_p2p_connection([self.node])

        block_gen_thread = BlockGenThread([self.node], self.log, num_txs=10000, interval_fixed=0.02)
        block_gen_thread.start()
        tx_n = 500000
        batch_size = 10
        send_tps = 20000
        all_txs = []
        gas_price = 1
        account_n = 1000

        generate = False
        if generate:
            f = open("encoded_tx", "wb")
            '''Test Random Transactions'''

            self.log.info("Setting up genesis secrets")
            balance_map = {}
            nonce_map = {}
            account_i = 0
            for prikey_str in open(self.conf_parameters["genesis_secrets"][1:-1], "r").readlines():
                prikey = decode_hex(prikey_str[:-1])
                balance_map[prikey] = 10000000000000000000000
                nonce_map[prikey] = 0
                account_i += 1
                if account_i == account_n:
                    break

            # genesis_key = default_config["GENESIS_PRI_KEY"]
            # balance_map = {genesis_key: default_config["TOTAL_COIN"]}
            # nonce_map = {genesis_key: 0}
            # # Initialize new accounts
            # new_keys = set()
            # for _ in range(account_n):
            #     value = int(balance_map[genesis_key] / (account_n * 2))
            #     receiver_sk, _ = ec_random_keys()
            #     new_keys.add(receiver_sk)
            #     tx = create_transaction(pri_key=genesis_key, receiver=priv_to_addr(receiver_sk), value=value,
            #                             nonce=nonce_map[genesis_key], gas_price=gas_price)
            #     all_txs.append(tx)
            #     balance_map[receiver_sk] = value
            #     nonce_map[genesis_key] += 1
            #     balance_map[genesis_key] -= value + gas_price * 21000
            # wait_for_account_stable()
            # for key in new_keys:
            #     nonce_map[key] = wait_for_initial_nonce_for_privkey(self.nodes[0], key)

            self.log.info("start to generate %d transactions", tx_n)
            account_list = list(balance_map)
            for i in range(tx_n):
                if i % 1000 == 0:
                    self.log.info("generated %d tx", i)
                sender_key = random.choice(account_list)
                if sender_key not in nonce_map:
                    nonce_map[sender_key] = wait_for_initial_nonce_for_privkey(self.nodes[0], sender_key)
                nonce = nonce_map[sender_key]
                value = 1
                receiver_sk = random.choice(account_list)
                balance_map[receiver_sk] += value
                # not enough transaction fee (gas_price * gas_limit) should not happen for now
                assert balance_map[sender_key] >= value + gas_price * 21000
                tx = create_transaction(pri_key=sender_key, receiver=priv_to_addr(receiver_sk), value=value, nonce=nonce,
                                        gas_price=gas_price)
                # self.log.debug("%s send %d to %s nonce=%d balance: sender=%s, receiver=%s", encode_hex(priv_to_addr(sender_key)), value, encode_hex(priv_to_addr(receiver_sk)), nonce, balance_map[sender_key], balance_map[receiver_sk])
                all_txs.append(tx)
                nonce_map[sender_key] = nonce + 1
                balance_map[sender_key] -= value + gas_price * 21000
            encoded_txs = []
            batch_tx = []
            i = 0
            for tx in all_txs:
                batch_tx.append(tx)
                i += 1
                if i  % batch_size == 0:
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
        start_time = time.time()
        i = 0
        for encoded in encoded_txs:
            i += 1
            if i * batch_size % send_tps == 0:
                time_used = time.time() - start_time
                time.sleep(i*batch_size/send_tps - time_used)
            self.node.p2p.send_protocol_packet(encoded + int_to_bytes(
                TRANSACTIONS))
        self.log.info(f"Time used to send {tx_n} transactions in {i} iterations: {time_used}")

        for k in balance_map:
                wait_until(lambda: self.check_account(k, balance_map), timeout=600)
        time_used = time.time() - start_time
        block_gen_thread.stop()
        block_gen_thread.join()
        self.log.info("Time used: %f seconds", time_used)
        self.log.info("Tx per second: %f", tx_n / time_used)

    def check_account(self, k, balance_map):
        addr = eth_utils.encode_hex(priv_to_addr(k))
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
