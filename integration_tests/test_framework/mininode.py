#!/usr/bin/env python3
"""Conflux P2P network half-a-node.

`P2PConnection: A low-level connection object to a node's P2P interface
P2PInterface: A high-level interface object for communicating to a node over P2P
"""
import time
from eth_utils import decode_hex

from integration_tests.conflux import utils
from integration_tests.conflux.config import DEFAULT_PY_TEST_CHAIN_ID
from integration_tests.conflux.messages import *
import asyncio
from collections import defaultdict
from io import BytesIO
import rlp
from rlp.sedes import big_endian_int, CountableList, boolean
import logging
import socket
import struct
import sys
import threading

from integration_tests.conflux.transactions import Transaction
from integration_tests.conflux.utils import hash32, hash20, sha3, int_to_bytes, sha3_256, ecrecover_to_pub, ec_random_keys, ecsign, \
    bytes_to_int, encode_int32, int_to_hex, int_to_32bytearray, zpad, rzpad
from integration_tests.test_framework.blocktools import make_genesis
from integration_tests.test_framework.util import wait_until, get_ip_address

logger = logging.getLogger("TestFramework.mininode")


class P2PConnection(asyncio.Protocol):
    """A low-level connection object to a node's P2P interface.

    This class is responsible for:

    - opening and closing the TCP connection to the node
    - reading bytes from and writing bytes to the socket
    - deserializing and serializing the P2P message header
    - logging messages as they are sent and received

    This class contains no logic for handling the P2P message payloads. It must be
    sub-classed and the on_message() callback overridden."""
    
    protocol: bytes

    def __init__(self):
        self.chain_id = None
        self._transport = None

    def set_chain_id(self, chain_id):
        self.chain_id = chain_id
    
    @property
    def is_connected(self):
        return self._transport is not None

    def peer_connect(self, dstaddr, dstport):
        assert not self.is_connected
        self.dstaddr = dstaddr
        self.dstport = dstport
        self.recvbuf = b""
        self.had_hello = False

        logger.debug('Connecting to Conflux Node: %s:%d' %
                     (self.dstaddr, self.dstport))
        
        loop = NetworkThread.network_event_loop
        conn_gen_unsafe = loop.create_connection(lambda: self, host=self.dstaddr, port=self.dstport)
        conn_gen = lambda: loop.call_soon_threadsafe(loop.create_task, conn_gen_unsafe)
        return conn_gen


    def peer_disconnect(self):
        NetworkThread.network_event_loop.call_soon_threadsafe(lambda: self._transport and self._transport.abort())

    # Connection and disconnection methods

    def connection_made(self, transport):
        """asyncio callback when a connection is opened."""
        assert not self._transport
        logger.debug("Connected & Listening: %s:%d" %
                        (self.dstaddr, self.dstport))
        self._transport = transport
        self.on_open()
        
    def on_open(self):
        pass

    def connection_lost(self, exc):
        """asyncio callback when a connection is closed."""
        if exc:
            logger.warning("Connection lost to {}:{} due to {}".format(self.dstaddr, self.dstport, exc))
        else:
            logger.debug("Closed connection to: %s:%d" % (self.dstaddr, self.dstport))
        self._transport = None
        self.recvbuf = b""
        self.on_close()


    def on_close(self):
        pass

    # Socket read methods

    def data_received(self, buf):
        """asyncio callback when data is read from the socket."""
        if len(buf) > 0:
            self.recvbuf += buf
            self._on_data()

    def read_connection_packet(self):
        if len(self.recvbuf) < 3:
            return None

        packet_size = struct.unpack("<L", rzpad(self.recvbuf[:3], 4))[0]
        if len(self.recvbuf) < 3 + packet_size:
            return

        self.recvbuf = self.recvbuf[3:]
        packet = self.recvbuf[:packet_size]
        self.recvbuf = self.recvbuf[packet_size:]

        if len(packet) > 3:
            packet = packet[-3:] + packet[:-3]

        return packet

    def assemble_connection_packet(self, data):
        data_len = struct.pack("<L", len(data))[:3]

        if len(data) > 3:
            return data_len + data[3:] + data[:3]
        else:
            return data_len + data

    def read_session_packet(self, packet):
        if packet[-2] == 0:
            return (packet[-1], None, packet[:-2])
        else:
            return (packet[-1], packet[-5:-2], packet[:-5])

    def assemble_session_packet(self, packet_id, protocol, payload):
        packet_id = struct.pack("<B", packet_id)
        if protocol is None:
            return payload + b'\x00' + packet_id
        else:
            return payload + protocol + b'\x01' + packet_id

    def read_protocol_msg(self, msg):
        return (msg[-1], msg[:-1])

    def assemble_protocol_msg(self, msg):
        return rlp.encode(msg) + int_to_bytes(get_msg_id(msg))

    def _on_data(self):
        """Try to read P2P messages from the recv buffer.

        This method reads data from the buffer in a loop. It deserializes,
        parses and verifies the P2P header, then passes the P2P payload to
        the on_message callback for processing."""
        try:
            while True:
                packet = self.read_connection_packet()
                if packet is None:
                    return

                if self.on_handshake(packet):
                    continue

                packet_id, protocol, payload = self.read_session_packet(packet)
                self._log_message("receive", packet_id)

                if packet_id != PACKET_HELLO and packet_id != PACKET_DISCONNECT and (not self.had_hello):
                    raise ValueError("bad protocol")

                if packet_id == PACKET_HELLO:
                    self.on_hello(payload)
                elif packet_id == PACKET_DISCONNECT:
                    disconnect = Disconnect(payload[0], payload[1:])
                    self.on_disconnect(disconnect)
                else:
                    assert packet_id == PACKET_PROTOCOL
                    self.on_protocol_packet(protocol, payload)
        except Exception as e:
            logger.exception('Error reading message: ' + repr(e))
            raise

    def on_handshake(self, payload) -> bool:
        return False

    def on_hello(self, payload):
        self.had_hello = True

    def on_disconnect(self, disconnect):
        self.on_close()

    def on_protocol_packet(self, protocol, payload):
        """Callback for processing a protocol-specific P2P payload. Must be overridden by derived class."""
        raise NotImplementedError

    def send_packet(self, packet_id, payload):
        """Send a P2P message over the socket.

        This method takes a P2P payload, builds the P2P header and adds
        the message to the send buffer to be sent over the socket."""
        self._log_message("send", packet_id)
        buf = self.assemble_session_packet(packet_id, None, payload)

        self.send_data(buf)


    def send_data(self, data):
        if not self.is_connected:
            raise IOError('Not connected, no pushbuf')

        buf = self.assemble_connection_packet(data)

        NetworkThread.network_event_loop.call_soon_threadsafe(lambda: self._transport and self._transport.write(buf))

    def send_protocol_packet(self, payload):
        """Send packet of protocols"""
        buf = self.assemble_session_packet(PACKET_PROTOCOL, self.protocol, payload)
        self.send_data(buf)

    def send_protocol_msg(self, msg):
        """Send packet of protocols"""
        payload = self.assemble_protocol_msg(msg)
        self.send_protocol_packet(payload)

    # Class utility methods

    def _log_message(self, direction, msg):
        """Logs a message being sent or received over the connection."""
        if direction == "send":
            log_message = "Send message to "
        elif direction == "receive":
            log_message = "Received message from "
        log_message += "%s:%d: %s" % (self.dstaddr,
                                      self.dstport, repr(msg)[:500])
        if len(log_message) > 500:
            log_message += "... (msg truncated)"
        logger.debug(log_message)


class P2PInterface(P2PConnection):
    """A high-level P2P interface class for communicating with a Conflux node.

    This class provides high-level callbacks for processing P2P message
    payloads, as well as convenience methods for interacting with the
    node over P2P.

    Individual testcases should subclass this and override the on_* methods
    if they want to alter message handling behaviour."""

    def __init__(self, genesis: str, remote=False):
        super().__init__()

        # Track number of messages of each type received and the most recent
        # message of each type
        self.message_count = defaultdict(int)
        self.protocol_message_count = defaultdict(int)
        self.last_message = {}
        self.last_protocol_message = {}

        # Default protocol version
        self.protocol = b'cfx'
        self.protocol_version = 3
        # Store genesis_hash
        self.genesis = decode_hex(genesis)
        self.best_block_hash = self.genesis
        self.blocks = {self.genesis: self.genesis}
        self.peer_pubkey = None
        self.priv_key, self.pub_key = ec_random_keys()
        x, y = self.pub_key
        self.key = "0x" + utils.encode_hex(bytes(int_to_32bytearray(x))) + utils.encode_hex(bytes(int_to_32bytearray(y)))
        self.had_status = False
        self.on_packet_func = {}
        self.remote = remote

    def peer_connect(self, *args, **kwargs):
        return super().peer_connect(*args, **kwargs)

    def wait_for_status(self, timeout=60):
        wait_until(lambda: self.had_status, timeout=timeout, lock=mininode_lock)

    def set_callback(self, msgid, func):
        self.on_packet_func[msgid] = func

    def reset_callback(self, msgid):
        del self.on_packet_func[msgid]

    # Message receiving methods

    def send_status(self):
        status = Status(
            ChainIdParams(self.chain_id),
            self.genesis, 0, 0, [self.best_block_hash])
        self.send_protocol_msg(status)

    def on_protocol_packet(self, protocol, payload):
        """Receive message and dispatch message to appropriate callback.

        We keep a count of how many of each message type has been received
        and the most recent message of each type."""
        with mininode_lock:
            try:
                assert(protocol == self.protocol)  # Possible to be false?
                packet_type, payload = self.read_protocol_msg(payload)
                self.protocol_message_count[packet_type] += 1
                msg = None
                msg_class = get_msg_class(packet_type)
                logger.debug("%s %s", packet_type, rlp.decode(payload))
                if msg_class is not None:
                    msg = rlp.decode(payload, msg_class)
                if packet_type == STATUS_V3:
                    self._log_message("receive", "STATUS, terminal_hashes:{}"
                                      .format([utils.encode_hex(i) for i in msg.terminal_block_hashes]))
                    self.had_status = True
                elif packet_type == GET_BLOCK_HEADERS:
                    self._log_message("receive", "GET_BLOCK_HEADERS of {}".format(msg.hashes))
                elif packet_type == GET_BLOCK_HEADER_CHAIN:
                    self._log_message("receive", "GET_BLOCK_HEADER_CHAIN of {} {}".format(msg.hash, msg.max_blocks))
                elif packet_type == GET_BLOCK_BODIES:
                    hashes = msg.hashes
                    self._log_message("receive", "GET_BLOCK_BODIES of {} blocks".format(len(hashes)))
                elif packet_type == GET_BLOCK_HEADERS_RESPONSE:
                    self._log_message("receive", "BLOCK_HEADERS of {} headers".format(len(msg.headers)))
                elif packet_type == GET_BLOCK_BODIES_RESPONSE:
                    self._log_message("receive", "BLOCK_BODIES of {} blocks".format(len(msg)))
                elif packet_type == NEW_BLOCK:
                    self._log_message("receive", "NEW_BLOCK, hash:{}".format(msg.block.block_header.hash))
                elif packet_type == GET_BLOCK_HASHES:
                    self._log_message("receive", "GET_BLOCK_HASHES, hash:{}, max_blocks:{}"
                                      .format(msg.hash, msg.max_blocks))
                elif packet_type == GET_BLOCK_HASHES_RESPONSE:
                    self._log_message("receive", "BLOCK_HASHES, {} hashes".format(len(msg.hashes)))
                elif packet_type == GET_TERMINAL_BLOCK_HASHES:
                    self._log_message("receive", "GET_TERMINAL_BLOCK_HASHES")
                elif packet_type == TRANSACTIONS:
                    self._log_message("receive", "TRANSACTIONS, {} transactions".format(len(msg.transactions)))
                elif packet_type == GET_TERMINAL_BLOCK_HASHES_RESPONSE:
                    self._log_message("receive", "TERMINAL_BLOCK_HASHES, {} hashes".format(len(msg.hashes)))
                elif packet_type == NEW_BLOCK_HASHES:
                    self._log_message("receive", "NEW_BLOCK_HASHES, {} hashes".format(len(msg.block_hashes)))
                elif packet_type == GET_BLOCKS_RESPONSE:
                    self._log_message("receive", "BLOCKS, {} blocks".format(len(msg.blocks)))
                elif packet_type == GET_CMPCT_BLOCKS_RESPONSE:
                    self._log_message("receive", "GET_CMPCT_BLOCKS_RESPONSE, {} blocks".format(len(msg.blocks)))
                elif packet_type == GET_BLOCK_TXN_RESPONSE:
                    self._log_message("receive", "GET_BLOCK_TXN_RESPONSE, block:{}".format(len(msg.block_hash)))
                elif packet_type == GET_BLOCKS:
                    self._log_message("receive", "GET_BLOCKS, {} hashes".format(len(msg.hashes)))
                    self.on_get_blocks(msg)
                elif packet_type == GET_CMPCT_BLOCKS:
                    self._log_message("receive", "GET_CMPCT_BLOCKS, {} hashes".format(len(msg.hashes)))
                    self.on_get_compact_blocks(msg)
                elif packet_type == GET_BLOCK_TXN:
                    self._log_message("receive", "GET_BLOCK_TXN, hash={}".format(len(msg.block_hash)))
                    self.on_get_blocktxn(msg)
                elif packet_type == GET_BLOCK_HASHES_BY_EPOCH:
                    self._log_message("receive", "GET_BLOCK_HASHES_BY_EPOCH, epochs: {}".format(msg.epochs))
                    self.on_get_block_hashes_by_epoch(msg)
                else:
                    self._log_message("receive", "Unknown packet {}".format(packet_type))
                    return
                if packet_type in self.on_packet_func and msg is not None:
                    self.on_packet_func[packet_type](self, msg)
            except:
                raise

    def on_hello(self, payload):
        hello = rlp.decode(payload, Hello)

        capabilities = []
        for c in hello.capabilities:
            capabilities.append((c.protocol, c.version))
        self._log_message(
            "receive", "Hello, capabilities:{}".format(capabilities))
        ip = [127, 0, 0, 1]
        if self.remote:
            ip = get_ip_address()
        endpoint = NodeEndpoint(address=bytes(ip), tcp_port=32325, udp_port=32325)
        # FIXME: Use a valid pos_public_key.
        hello = Hello(DEFAULT_PY_TEST_CHAIN_ID, [Capability(self.protocol, self.protocol_version)], endpoint,
                      decode_hex('ac4a9103a323cf3a0d64712de2cbacf6df5d4c2cad7458aa612696f60a6de0a0958da59c7736b71cf24139b1be94be1503efefa083263438fd07edd1e03246683ff58da8bdde286c321032765258d0c34f'))

        self.send_packet(PACKET_HELLO, rlp.encode(hello, Hello))
        self.had_hello = True
        self.send_status()

    # Callback methods. Can be overridden by subclasses in individual test
    # cases to provide custom message handling behaviour.

    def on_open(self):
        self.handshake = Handshake(self)
        self.handshake.write_auth()

    def on_close(self): pass

    def on_handshake(self, payload) -> bool:
        if self.handshake.state == "ReadingAck":
            self.handshake.read_ack(payload)
            return True

        assert self.handshake.state == "StartSession"

        return False

    def on_get_blocks(self, msg):
        resp = Blocks(reqid=msg.reqid, blocks=[])
        self.send_protocol_msg(resp)

    def on_get_compact_blocks(self, msg):
        resp = GetCompactBlocksResponse(reqid=msg.reqid, compact_blocks=[], blocks=[])
        self.send_protocol_msg(resp)

    def on_get_blocktxn(self, msg):
        resp = GetBlockTxnResponse(reqid=msg.reqid, block_hash=b'\x00'*32, block_txn=[])
        self.send_protocol_msg(resp)

    def on_get_block_hashes_by_epoch(self, msg):
        resp = BlockHashes(reqid=msg.reqid, hashes=[])
        self.send_protocol_msg(resp)


# One lock for synchronizing all data access between the networking thread (see
# NetworkThread below) and the thread running the test logic.  For simplicity,
# P2PConnection acquires this lock whenever delivering a message to a P2PInterface,
# and whenever adding anything to the send buffer (in send_message()).  This
# lock should be acquired in the thread running the test logic to synchronize
# access to any data shared with the P2PInterface or P2PConnection.
mininode_lock = threading.RLock()

class DefaultNode(P2PInterface):
    def __init__(self, genesis: str, remote = False):
        super().__init__(genesis, remote)

class NetworkThread(threading.Thread):
    network_event_loop: asyncio.AbstractEventLoop = None  # type: ignore

    def __init__(self):
        super().__init__(name="NetworkThread")
        # There is only one event loop and no more than one thread must be created
        assert not self.network_event_loop

        NetworkThread.network_event_loop = asyncio.new_event_loop()

    def run(self):
        """Start the network thread."""
        self.network_event_loop.run_forever()

    def close(self, timeout=10):
        """Close the connections and network event loop."""
        self.network_event_loop.call_soon_threadsafe(self.network_event_loop.stop)
        wait_until(lambda: not self.network_event_loop.is_running(), timeout=timeout)
        self.network_event_loop.close()
        self.join(timeout)
        NetworkThread.network_event_loop = None  # type: ignore


def start_p2p_connection(nodes: list, remote=False):
    if len(nodes) == 0:
        return
    p2p_connections = []
    # TODO(lpl): Figure out why pos slows down node starting.
    time.sleep(1)
    genesis = nodes[0].cfx_getBlockByEpochNumber("0x0", False)["hash"]

    for node in nodes:
        conn = DefaultNode(genesis, remote)
        p2p_connections.append(conn)
        node.add_p2p_connection(conn)

    for p2p in p2p_connections:
        p2p.wait_for_status()

    return p2p_connections

class Handshake:
    def __init__(self, peer: P2PInterface):
        self.peer = peer
        self.state = "New"

    def write_auth(self):
        node_id = utils.decode_hex(self.peer.key)
        self.peer.send_data(node_id)
        self.state = "ReadingAck"

    def read_ack(self, remote_node_id: bytes):
        assert len(remote_node_id) == 64, "invalid node id length {}".format(len(remote_node_id))
        self.peer.peer_key = utils.encode_hex(remote_node_id)
        self.state = "StartSession"
