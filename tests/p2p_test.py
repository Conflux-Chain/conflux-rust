#!/usr/bin/env python3
from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt

from conflux import utils
from conflux.rpc import RpcClient
from conflux.utils import encode_hex, bytes_to_int, privtoaddr, parse_as_int
from test_framework.blocktools import create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 8
        self.conf_parameters["generate_tx"] = "true"
        # Every node generates 1 tx every second
        self.conf_parameters["generate_tx_period_us"] = "100000"
        self.conf_parameters["log_level"] = "\"debug\""

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        block_number = 4000

        # Setup balance for each node
        client = RpcClient(self.nodes[0])
        for i in range(self.num_nodes):
            pub_key = self.nodes[i].key
            addr = self.nodes[i].addr
            self.log.info("%d has addr=%s pubkey=%s", i, encode_hex(addr), pub_key)
            tx = client.new_tx(value=int(default_config["TOTAL_COIN"]/self.num_nodes) - 21000, receiver=encode_hex(addr), nonce=i)
            client.send_tx(tx)
        for i in range(1, block_number):
            chosen_peer = random.randint(0, self.num_nodes - 1)
            if random.random() <= 0.01:
                self.log.info("stop %s", chosen_peer)
                self.stop_node(chosen_peer)
                self.start_node(chosen_peer, phase_to_wait=("NormalSyncPhase"))
            self.log.debug("%d try to generate", chosen_peer)
            block_hash = RpcClient(self.nodes[chosen_peer]).generate_block(1000)
            self.log.info("%d generate block %s", chosen_peer, block_hash)
            time.sleep(random.random()/30)
        wait_for_block_count(self.nodes[0], block_number)
        sync_blocks(self.nodes, timeout=30)
        hasha = self.nodes[0].getbestblockhash()
        block_a = client.block_by_hash(hasha)
        self.log.info("Final height = %s", block_a['height'])
        self.log.info("Pass")


if __name__ == "__main__":
    P2PTest().main()
