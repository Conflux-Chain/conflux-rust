#!/usr/bin/env python3
import struct
import time
from rlp.sedes import Binary, BigEndianInt

from conflux import utils
from conflux.utils import encode_hex, bytes_to_int, int_to_hex
from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class MessageTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4

    def setup_network(self):
        self.setup_nodes()
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, i, i + 1)

    def run_test(self):
        default_node = start_p2p_connection([self.nodes[0]])[0]

        # Use the mininode and blocktools functionality to manually build a block
        # Calling the generate() rpc is easier, but this allows us to exactly
        # control the blocks and transactions.
        blocks = [default_node.genesis.block_header.hash]
        new_block = create_block(blocks[0], 1)
        new_transaction = create_transaction(gas_price = 1000)

        # This message is not used in current Conflux sync protocol
        # self.log.info("Send GetBlockHashes message")
        # self.send_msg(GetBlockHashes(hash=blocks[0], max_blocks=1))
        # wait_until(lambda: default_node.msg_count >= 1)
        def on_block_headers(node, msg):
            self.log.info("Received %d headers", len(msg.headers))
            for header in msg.headers:
                self.log.info("Block header: %s", encode_hex(header.hash))
        handler = WaitHandler(default_node, GET_BLOCK_HEADERS_RESPONSE, on_block_headers)
        self.log.info("Send GetBlockHeaders message")
        self.send_msg(GetBlockHeaders(hash=blocks[0], max_blocks=1))
        handler.wait()
        # This message is not used in current Conflux sync protocol
        # self.log.info("Send GetBlockBoies message")
        # self.send_msg(GetBlockBodies(hashes=[blocks[0]]))
        # wait_until(lambda: default_node.msg_count >= 3)
        self.log.info("Send GetBlocks message")
        handler = WaitHandler(default_node, GET_BLOCKS_RESPONSE)
        self.send_msg(GetBlocks(with_public=0, hashes=[blocks[0]]))
        handler.wait()
        self.log.info("Received GetBlock response")

        self.send_msg(NewBlockHashes([new_block.block_header.hash]))
        self.send_msg(NewBlock(block=new_block))
        self.log.info("Send GetTerminalBLockHashes message")
        self.send_msg(GetTerminalBlockHashes())
        handler = WaitHandler(default_node, GET_TERMINAL_BLOCK_HASHES_RESPONSE)
        handler.wait()
        self.log.info("Received TerminalBlockHashes")

        # FIXME: Currently, the transaction broadcast logic 
        # has not been finished. Enable it later.

        #self.send_msg(Transactions(transactions=[new_transaction]))
        #time.sleep(5)
        #res = self.nodes[0].getstatus()
        #assert_equal(1, res['pendingTxNumber'])
        #res = self.nodes[1].getstatus()
        #assert_equal(1, res['pendingTxNumber'])
        #self.log.info("Pass")

        self.test_socket_msg(self.nodes[0])

    def send_msg(self, msg):
        self.nodes[0].p2p.send_protocol_msg(msg)

    def test_socket_msg(self, node):
        self.log.info("testing invalid socket message ...")

        # buf = struct.pack("<L", len(payload) + 1)[:3]
        # buf += struct.pack("<B", packet_id)
        # buf += payload

        # empty packet
        buf = struct.pack("<L", 0)[:3]
        assert node.p2p.state == "connected"
        node.p2p.send(buf)
        # node should disconnect this p2p connection
        wait_until(lambda: node.p2p.state != "connected")

        # empty payload
        p2p = start_p2p_connection([self.nodes[0]])[0]
        p2p.send_packet(PACKET_HELLO, b'')
        wait_until(lambda: p2p.state != "connected")

        p2p = start_p2p_connection([self.nodes[0]])[0]
        p2p.send_packet(PACKET_DISCONNECT, b'')
        wait_until(lambda: p2p.state != "connected")

        p2p = start_p2p_connection([self.nodes[0]])[0]
        p2p.send_packet(PACKET_PROTOCOL, b'')
        wait_until(lambda: p2p.state != "connected")

        # legel payload
        p2p = start_p2p_connection([self.nodes[0]])[0]
        p2p.send_packet(PACKET_PING, b'')
        p2p.send_packet(PACKET_PONG, b'')
        time.sleep(1)  # Give node 1s to disconnect if needed
        assert p2p.state == "connected"


if __name__ == "__main__":
    MessageTest().main()
