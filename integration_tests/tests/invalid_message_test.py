import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework

from integration_tests.conflux import utils, trie
from integration_tests.conflux.rpc import RpcClient
from integration_tests.conflux.utils import encode_hex, bytes_to_int, int_to_hex, str_to_bytes
from integration_tests.test_framework.blocktools import create_block, create_transaction
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.mininode import *
from integration_tests.test_framework.test_node import TestNode
from integration_tests.test_framework.util import *

class InvalidMessageTestClass(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        # Disable 1559 for RPC tests temporarily
        self.conf_parameters["cip1559_transition_height"] = str(99999999)

    def setup_network(self):
        self.setup_nodes()
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, i, i + 1)
            self.nodes[i].test_addLatency(self.nodes[i+1].key, 1000)
            self.nodes[i+1].test_addLatency(self.nodes[i].key, 1000)


    def send_msg(self, msg):
        self.nodes[0].p2p.send_protocol_msg(msg)

    def reconnect(self, node: TestNode):
        node.disconnect_p2ps()
        # Wait for disconnection
        time.sleep(0.5)
        genesis = node.cfx_getBlockByEpochNumber("0x0", False)["hash"]
        node.add_p2p_connection(DefaultNode(genesis))
        node.p2p.wait_for_status()

    def _test_invalid_packet(self):
        self.log.info("Test invalid packet")
        # self.nodes[0].p2p.send_packet(0, b'')
        # self.nodes[0].p2p.send_packet(0xff, b'')
        # self.nodes[0].p2p.send_packet(PACKET_PROTOCOL, b'')
        block_hash = decode_hex(self.nodes[0].test_generateEmptyBlocks(1)[0])
        wait = [True]

        h = WaitHandler(self.nodes[0].p2p, GET_BLOCK_HEADERS_RESPONSE)
        self.nodes[0].p2p.send_protocol_msg(GetBlockHeaders(hashes=[block_hash]))
        h.wait()

        def assert_length(_node, msg):
            assert_equal(len(msg.headers), 1)
        h = WaitHandler(self.nodes[0].p2p, GET_BLOCK_HEADERS_RESPONSE, assert_length)
        self.nodes[0].p2p.send_protocol_msg(GetBlockHeaders(hashes=[block_hash]))
        h.wait()
        self.reconnect(self.nodes[0])

    def _test_new_block(self):
        self.log.info("Test New Block")
        client = RpcClient(self.nodes[0])
        best_block = client.best_block_hash()
        best_epoch = client.epoch_number()
        new_block = create_block(decode_hex(best_block), best_epoch + 1)
        self.send_msg(NewBlock(block=new_block))
        wait_until(lambda: self.nodes[0].best_block_hash() == new_block.hash_hex())

        # Wrong payload
        self.nodes[0].p2p.send_protocol_packet(rlp.encode([0]) + int_to_bytes(NEW_BLOCK))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].test_getBlockCount(), 3)
        self.reconnect(self.nodes[0])

        # Wrong-length parent hash
        invalid_block = create_block(parent_hash=b'', height=2)
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].test_getBlockCount(), 3)
        self.reconnect(self.nodes[0])

        # Wrong-length author
        invalid_block = create_block(author=b'', height=2)
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].test_getBlockCount(), 3)
        self.reconnect(self.nodes[0])

        # Wrong-length root
        invalid_block = create_block(deferred_state_root=b'', height=2, deferred_receipts_root=b'')
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].test_getBlockCount(), 3)
        self.reconnect(self.nodes[0])

        # Nonexistent parent
        invalid_block = create_block(parent_hash=b'\x00' * 32, height=2)
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].test_getBlockCount(), 3)
        self.reconnect(self.nodes[0])

        # Invalid height
        invalid_block = create_block(new_block.hash, 1)
        self.send_msg(NewBlock(block=invalid_block))
        time.sleep(1)
        assert_equal(self.nodes[0].best_block_hash(), new_block.hash_hex())
        assert_equal(self.nodes[0].test_getBlockCount(), 3)
        self.reconnect(self.nodes[0])

        sync_blocks(self.nodes)

        # TODO Generate some random blocks that have wrong ref edges
        pass
    
@pytest.fixture(scope="module")
def framework_class():
    return InvalidMessageTestClass

def test_invalid_message(network: InvalidMessageTestClass):
    start_p2p_connection([network.nodes[0]])

    network._test_invalid_packet()
    network._test_new_block()
