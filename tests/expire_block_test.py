#!/usr/bin/env python3
from rlp.sedes import Binary, BigEndianInt

from conflux import utils, trie
from conflux.utils import encode_hex, bytes_to_int, int_to_hex, str_to_bytes
from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class ExpireBlockTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "15"
        self.conf_parameters["era_epoch_count"] = "100"
        self.conf_parameters["dev_snapshot_epoch_count"] = "50"
        self.conf_parameters["anticone_penalty_ratio"] = "10"
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        self.nodes[0].add_p2p_connection(P2PInterface())
        self.nodes[1].add_p2p_connection(P2PInterface())
        network_thread_start()
        self.nodes[0].p2p.wait_for_status()
        self.nodes[1].p2p.wait_for_status()

    def send_msg(self, node, msg):
        node.p2p.send_protocol_msg(msg)

    def run_test(self):
        self.test_expire_block_gc()
        self.test_recover_expire_block()

    def test_recover_expire_block(self):
        node = self.nodes[1]

        blocks = [node.best_block_hash()]
        for i in range(400):
            new_hash = node.generatefixedblock(blocks[-1], [], 0, False)
            blocks.append(new_hash)
            self.log.info("generate block={}".format(new_hash))
        wait_until(lambda: node.best_block_hash() == new_hash)
        out_block = create_block(parent_hash=bytes.fromhex(blocks[50][2:]), height=51, referee_hashes=[bytes.fromhex(blocks[400][2:])])
        self.send_msg(node, NewBlock(block=out_block))
        time.sleep(3)
        node.expireblockgc(2)
        wait_until(lambda: node.getblockcount() == 402)

    def test_expire_block_gc(self):
        node = self.nodes[0]

        blocks = [node.p2p.genesis]
        for i in range(10):
            new_block = create_block(blocks[-1].hash, i + 1)
            blocks.append(new_block)
        for i in range(1, 6):
            self.send_msg(node, NewBlock(block=blocks[i]))
            wait_until(lambda: node.best_block_hash() == blocks[i].hash_hex())
        for i in range(7, 9):
            self.send_msg(node, NewBlock(block=blocks[i]))
            wait_until(lambda: node.best_block_hash() == blocks[5].hash_hex())
        time.sleep(3)
        node.expireblockgc(2)
        for i in range(7, 9):
            self.send_msg(node, NewBlock(block=blocks[i]))
            wait_until(lambda: node.best_block_hash() == blocks[5].hash_hex())
        self.send_msg(node, NewBlock(block=blocks[6]))
        wait_until(lambda: node.best_block_hash() == blocks[8].hash_hex())
        for i in range(9, 11):
            self.send_msg(node, NewBlock(block=blocks[i]))
            wait_until(lambda: node.best_block_hash() == blocks[i].hash_hex())

if __name__ == "__main__":
    ExpireBlockTest().main()