import pytest
import struct


from integration_tests.conflux import utils
from eth_utils.hexadecimal import decode_hex, encode_hex
from integration_tests.test_framework.blocktools import create_block
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.mininode import *
from integration_tests.test_framework.util import *

class MessageTestClass(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        # Disable 1559 for RPC tests temporarily
        self.conf_parameters["cip1559_transition_height"] = str(99999999)

    def setup_network(self):
        self.setup_nodes()
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, i, i + 1)
    
    def send_msg(self, msg):
        self.nodes[0].p2p.send_protocol_msg(msg)

    def test_socket_msg(self, node):
        self.log.info("testing invalid socket message ...")

        # empty packet
        buf = struct.pack("<L", 0)[:3]
        assert node.p2p.is_connected
        node.p2p.send_data(buf)
        # node should disconnect this p2p connection
        wait_until(lambda: node.p2p.is_connected == False, timeout=3)

        p2p = start_p2p_connection([self.nodes[0]])[0]  # type: ignore
        p2p.send_packet(PACKET_DISCONNECT, b'')
        wait_until(lambda: p2p.is_connected == False, timeout=3)

        p2p = start_p2p_connection([self.nodes[0]])[0]  # type: ignore
        p2p.send_packet(PACKET_PROTOCOL, b'')
        wait_until(lambda: p2p.is_connected == False, timeout=3)

@pytest.fixture(scope="module")
def framework_class():
    return MessageTestClass

def test_message(network: MessageTestClass):
    default_node = start_p2p_connection([network.nodes[0]])[0]  # type: ignore

    # Use the mininode and blocktools functionality to manually build a block
    # Calling the test_generateEmptyBlocks() rpc is easier, but this allows us to exactly
    # control the blocks and transactions.
    block_hash = network.nodes[0].test_generateEmptyBlocks(1)[0]
    blocks = [decode_hex(block_hash)]
    new_block = create_block(blocks[0], 2)

    # This message is not used in current Conflux sync protocol
    # network.log.info("Send GetBlockHashes message")
    # network.send_msg(GetBlockHashes(hash=blocks[0], max_blocks=1))
    # wait_until(lambda: default_node.msg_count >= 1)
    def on_block_headers(node, msg):
        network.log.info("Received %d headers", len(msg.headers))
        for header in msg.headers:
            network.log.info("Block header: %s", encode_hex(header.hash))
    handler = WaitHandler(default_node, GET_BLOCK_HEADERS_RESPONSE, on_block_headers)
    network.log.info("Send GetBlockHeaders message")
    network.send_msg(GetBlockHeaders(hashes=[blocks[0]]))
    handler.wait()
    # This message is not used in current Conflux sync protocol
    # network.log.info("Send GetBlockBoies message")
    # network.send_msg(GetBlockBodies(hashes=[blocks[0]]))
    # wait_until(lambda: default_node.msg_count >= 3)
    network.log.info("Send GetBlocks message")
    handler = WaitHandler(default_node, GET_BLOCKS_RESPONSE)
    network.send_msg(GetBlocks(with_public=False, hashes=[blocks[0]]))
    handler.wait()
    network.log.info("Received GetBlock response")

    network.send_msg(NewBlockHashes([new_block.block_header.hash]))
    network.send_msg(NewBlock(block=new_block))
    network.log.info("Send GetTerminalBLockHashes message")
    network.send_msg(GetTerminalBlockHashes())
    handler = WaitHandler(default_node, GET_TERMINAL_BLOCK_HASHES_RESPONSE)
    handler.wait()
    network.log.info("Received TerminalBlockHashes")
    

    network.test_socket_msg(network.nodes[0])
