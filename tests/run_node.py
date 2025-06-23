#!/usr/bin/env python3
from conflux.utils import encode_hex, bytes_to_int, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
import time

class TransactionTest(DefaultConfluxTestFramework):
    def run_test(self):
        genesis_key = default_config["GENESIS_PRI_KEY"]
        balance_map = {genesis_key: default_config["TOTAL_COIN"]}
        addr = eth_utils.encode_hex(priv_to_addr(genesis_key))
        self.log.info("Initial State: (sk:%d, addr:%s, balance:%d)", bytes_to_int(genesis_key),
                     addr, balance_map[genesis_key])
        self.log.info("http://127.0.0.1:{}".format(self.nodes[0].rpcport))
        nonce_map = {genesis_key: 0}
        block_gen_thread = BlockGenThread(self.nodes, self.log, interval_base=0.2)
        block_gen_thread.start()
        
        # print(self.client.get_balance(addr))
        while True:
            self.log.info("Current number %d", self.client.epoch_number())
            time.sleep(5)

        
if __name__ == "__main__":
    TransactionTest().main()
