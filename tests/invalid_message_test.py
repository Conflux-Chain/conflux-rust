#!/usr/bin/env python3
from rlp.sedes import Binary, BigEndianInt

from conflux import utils, trie
from conflux.utils import encode_hex, bytes_to_int, int_to_hex, str_to_bytes
from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.test_node import TestNode
from test_framework.util import *


class InvalidMessageTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4

    def setup_network(self):
        self.setup_nodes()
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, i, i + 1)
            self.nodes[i].addlatency(self.nodes[i+1].key, 1000)
            self.nodes[i+1].addlatency(self.nodes[i].key, 1000)

    def run_test(self):
        start_p2p_connection([self.nodes[0]])

        self._test_invalid_packet()
        self._test_new_block()

    def send_msg(self, msg):
        self.nodes[0].p2p.send_protocol_msg(msg)

    def reconnect(self, node: TestNode):
        node.disconnect_p2ps()
        # Wait for disconnection
        time.sleep(0.5)
        node.add_p2p_connection(DefaultNode())
        network_thread_start()
        node.p2p.wait_for_status()

    def _test_invalid_packet(self):
        self.log.info("Test invalid packet")
        # self.nodes[0].p2p.send_packet(0, b'')
        # self.nodes[0].p2p.send_packet(0xff, b'')
        # self.nodes[0].p2p.send_packet(PACKET_PROTOCOL, b'')
        wait = [True]

        h = WaitHandler(self.nodes[0].p2p, GET_BLOCK_HEADERS_RESPONSE)
        self.nodes[0].p2p.send_protocol_msg(GetBlockHeaders(hashes=[self.nodes[0].p2p.genesis.hash]))
        h.wait()

        def assert_length(_node, msg):
            assert_equal(len(msg.headers), 1)
        h = WaitHandler(self.nodes[0].p2p, GET_BLOCK_HEADERS_RESPONSE, assert_length)
        self.nodes[0].p2p.send_protocol_msg(GetBlockHeaders(hashes=[self.nodes[0].p2p.genesis.hash]))
        h.wait()
        self.reconnect(self.nodes[0])

    def _test_new_block(self):
        self.log.info("Test New Block")
        genesis = self.nodes[0].p2p.genesis
        new_block = create_block(genesis.hash, 1)
        self.send_msg(NewBlock(block=new_block))
        wait_until(lambda: self.nodes[0].best_block_hash() == new_block.hash_hex())

        # Wrong payload
        self.nodes[0].p2p.send_protocol_packet(rlp.encode([0]) + int_to_bytes(NEW_BLOCK))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].getblockcount(), 2)
        self.reconnect(self.nodes[0])

        # Wrong-length parent hash
        invalid_block = create_block(parent_hash=b'', height=2)
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].getblockcount(), 2)
        self.reconnect(self.nodes[0])

        # Wrong-length author
        invalid_block = create_block(author=b'', height=2)
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].getblockcount(), 2)
        self.reconnect(self.nodes[0])

        # Wrong-length root
        invalid_block = create_block(deferred_state_root=b'', height=2, deferred_receipts_root=b'')
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].getblockcount(), 2)
        self.reconnect(self.nodes[0])

        # Nonexistent parent
        invalid_block = create_block(parent_hash=b'\x00' * 32, height=2)
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].getblockcount(), 2)
        self.reconnect(self.nodes[0])

        # Invalid height
        invalid_block = create_block(new_block.hash, 1)
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].getblockcount(), 2)
        self.reconnect(self.nodes[0])

        sync_blocks(self.nodes)

        # TODO Generate some random blocks that have wrong ref edges
        pass


if __name__ == "__main__":
    # FIXME fix this failed test
    InvalidMessageTest().main()
