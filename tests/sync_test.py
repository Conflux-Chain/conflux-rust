#!/usr/bin/env python3
from eth_utils import decode_hex, encode_hex

from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *


class SyncTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        for i in range(self.num_nodes):
            self.start_node(i)
        for i in range(1, self.num_nodes - 1):
            connect_nodes(self.nodes, i, i+1)

    def run_test(self):
        block_number = 100

        start_p2p_connection(self.nodes)
        
        best_block = self.nodes[1].generate_empty_blocks(1)[0]
        block1 = create_block(parent_hash=decode_hex(best_block), height=2)
        block2 = create_block(parent_hash=decode_hex(best_block), height=2, author=b'\x01' * 20)
        self.nodes[1].p2p.send_protocol_msg(NewBlock(block=block1))
        self.nodes[1].p2p.send_protocol_msg(NewBlock(block=block2))
        best_block = max(block1.hash, block2.hash)
        ref_block = min(block1.hash, block2.hash)
        block3 = create_block(parent_hash=best_block, height=3, referee_hashes=[ref_block])
        self.nodes[1].p2p.send_protocol_msg(NewBlock(block=block3))
        for block in [block1, block2, block3]:
            print(encode_hex(block.hash))
        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes, timeout=5)
        best_block = self.nodes[0].best_block_hash()
        print("best from rust: %s \nbest from local: %s\n" % (best_block, encode_hex(block3.hash)))
        assert_equal(best_block, encode_hex(block3.hash))
        self.log.info("Pass 1")

        disconnect_nodes(self.nodes, 0, 1)
        block1 = create_block(parent_hash=decode_hex(best_block), height=4)
        block2 = create_block(parent_hash=decode_hex(best_block), height=4, author=b'\x01' * 20)
        self.nodes[0].p2p.send_protocol_msg(NewBlock(block=block1))
        self.nodes[1].p2p.send_protocol_msg(NewBlock(block=block2))
        connect_nodes(self.nodes, 0, 1)
        wait_for_block_count(self.nodes[1], 7)
        sync_blocks(self.nodes, timeout=5)
        self.log.info("Pass 2")

        disconnect_nodes(self.nodes, 0, 1)
        for i in range(block_number):
            chosen_peer = random.randint(1, self.num_nodes - 1)
            block_hash = self.nodes[chosen_peer].generate_empty_blocks(1)
            self.log.info("%s generate block %s", chosen_peer, block_hash)
        wait_for_block_count(self.nodes[1], block_number + 7)
        sync_blocks(self.nodes[1:], timeout=10)
        self.log.info("blocks sync successfully between old nodes")
        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes, timeout=30)
        self.log.info("Pass 3")


if __name__ == "__main__":
    SyncTest().main()
