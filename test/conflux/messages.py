#!/usr/bin/env python3
"""Conflux P2P network half-a-node.

`P2PConnection: A low-level connection object to a node's P2P interface
P2PInterface: A high-level interface object for communicating to a node over P2P
"""

import asyncore
from collections import defaultdict
from io import BytesIO

import eth_utils
import rlp
from rlp.exceptions import ObjectSerializationError, ObjectDeserializationError
from rlp.sedes import binary, big_endian_int, CountableList, boolean
import logging
import socket
import struct
import sys
import threading

from conflux import trie
from conflux.config import default_config
from conflux.transactions import Transaction
from conflux.utils import hash32, hash20, sha3, bytes_to_int
from test_framework.util import wait_until

logger = logging.getLogger("TestFramework.mininode")


PACKET_HELLO = 0x80
PACKET_DISCONNECT = 0x01
PACKET_PING = 0x02
PACKET_PONG = 0x03
PACKET_PROTOCOL = 0x10

STATUS = 0x00
NEW_BLOCK_HASHES = 0x01
TRANSACTIONS = 0x02

GET_BLOCK_HASHES = 0x03
GET_BLOCK_HASHES_RESPONSE = 0x04
GET_BLOCK_HEADERS = 0x05
GET_BLOCK_HEADERS_RESPONSE = 0x06
GET_BLOCK_BODIES = 0x07
GET_BLOCK_BODIES_RESPONSE = 0x08
NEW_BLOCK = 0x09
GET_TERMINAL_BLOCK_HASHES_RESPONSE = 0x0a
GET_TERMINAL_BLOCK_HASHES = 0x0b
GET_BLOCKS = 0x0c
GET_BLOCKS_RESPONSE = 0x0d
GET_BLOCKS_WITH_PUBLIC_RESPONSE = 0x0e
GET_CMPCT_BLOCKS = 0x0f
GET_CMPCT_BLOCKS_RESPONSE = 0x10
GET_BLOCK_TXN = 0x11
GET_BLOCK_TXN_RESPONSE = 0x12

GET_BLOCK_HASHES_BY_EPOCH = 0x17

class Capability(rlp.Serializable):
    fields = [
        ("protocol", binary),
        ("version", big_endian_int)
    ]


class NodeEndpoint(rlp.Serializable):
    fields = [
        ("address", binary),
        ("udp_port", big_endian_int),
        ("port", big_endian_int)
    ]


class Hello(rlp.Serializable):
    fields = [
        ("capabilities", CountableList(Capability)),
        ("node_endpoint", NodeEndpoint)
    ]


class Disconnect(rlp.Serializable):
    fields = [
        ("reason", big_endian_int)
    ]


class Status(rlp.Serializable):
    fields = [
        ("protocol_version", big_endian_int),
        ("network_id", big_endian_int),
        ("genesis_hash", hash32),
        ("best_epoch", big_endian_int),
        ("terminal_block_hashes", CountableList(hash32)),
    ]


class NewBlockHashes(rlp.Serializable):
    def __init__(self, block_hashes=[]):
        assert is_sequence(block_hashes)
        self.block_hashes = block_hashes

    @classmethod
    def serializable(cls, obj):
        if is_sequence(obj.block_hashes):
            return True
        else:
            return False

    @classmethod
    def serialize(cls, obj):
        return CountableList(hash32).serialize(obj.block_hashes)

    @classmethod
    def deserialize(cls, serial):
        return cls(block_hashes=CountableList(hash32).deserialize(serial))


class Transactions:
    def __init__(self, transactions=[]):
        assert is_sequence(transactions)
        self.transactions = transactions

    @classmethod
    def serializable(cls, obj):
        if is_sequence(obj.transactions):
            return True
        else:
            return False

    @classmethod
    def serialize(cls, obj):
        return CountableList(Transaction).serialize(obj.transactions)

    @classmethod
    def deserialize(cls, serial):
        return cls(transactions=CountableList(Transaction).deserialize(serial))


class GetBlockHashes(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("hash", hash32),
        ("max_blocks", big_endian_int)
    ]

    def __init__(self, hash, max_blocks, reqid=0):
        super().__init__(
            reqid=reqid,
            hash=hash,
            max_blocks=max_blocks,
        )


class GetBlockHashesByEpoch(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("epoch_number", big_endian_int),
    ]

    def __init__(self, epoch_number, reqid=0):
        super().__init__(
            reqid=reqid,
            epoch_number=epoch_number
        )


class BlockHashes(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("hashes", CountableList(hash32)),
    ]


class GetBlockHeaders(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("hash", hash32),
        ("max_blocks", big_endian_int),
    ]

    def __init__(self, hash, max_blocks, reqid=0):
        super().__init__(
            reqid=reqid,
            hash=hash,
            max_blocks=max_blocks
        )


class BlockHeader(rlp.Serializable):
    fields = [
        ("parent_hash", binary),
        ("height", big_endian_int),
        ("timestamp", big_endian_int),
        ("author", binary),
        ("transactions_root", binary),
        ("deferred_state_root", binary),
        ("deferred_receipts_root", binary),
        ("difficulty", big_endian_int),
        ("adaptive", big_endian_int),
        ("gas_limit", big_endian_int),
        ("referee_hashes", CountableList(binary)),
        ("nonce", big_endian_int),
    ]

    def __init__(self,
                 parent_hash=default_config['GENESIS_PREVHASH'],
                 height=0,
                 timestamp=0,
                 author=default_config['GENESIS_COINBASE'],
                 transactions_root=trie.BLANK_ROOT,
                 deferred_state_root=trie.BLANK_ROOT,
                 deferred_receipts_root=trie.BLANK_ROOT,
                 difficulty=default_config['GENESIS_DIFFICULTY'],
                 gas_limit=0,
                 referee_hashes=[],
                 adaptive=0,
                 nonce=0):
        # at the beginning of a method, locals() is a dict of all arguments
        fields = {k: v for k, v in locals().items() if
                  k not in ['self', '__class__']}
        self.block = None
        super(BlockHeader, self).__init__(**fields)

    @property
    def hash(self):
        return sha3(rlp.encode(self))

    def get_hex_hash(self):
        return eth_utils.encode_hex(self.hash)

    def problem_hash(self):
        return sha3(rlp.encode(self.without_nonce()))

    def pow_decimal(self):
        return bytes_to_int(sha3(rlp.encode([self.problem_hash(), self.nonce])))

    def without_nonce(self):
        fields = {field: getattr(self, field) for field in BlockHeaderWithoutNonce._meta.field_names}
        return BlockHeaderWithoutNonce(**fields)


class BlockHeaderWithoutNonce(rlp.Serializable):
    fields = [
        (field, sedes) for field, sedes in BlockHeader._meta.fields if
        field not in ["nonce"]
    ]


# class BlockHeaders(CountableList(BlockHeader)):
#     fields = [
#         ("headers", CountableList(BlockHeader))
#     ]
class BlockHeaders(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("headers", CountableList(BlockHeader)),
    ]


class GetBlockBodies(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("hashes", CountableList(hash32)),
    ]

    def __init__(self, reqid=0, hashes=[]):
        super().__init__(
            reqid=reqid,
            hashes=hashes
        )


class Block(rlp.Serializable):
    fields = [
        ("block_header", BlockHeader),
        ("transactions", CountableList(Transaction))
    ]

    def __init__(self, block_header, transactions=None):
        super(Block, self).__init__(
            block_header=block_header,
            transactions=(transactions or []),
        )

    @property
    def hash(self):
        return self.block_header.hash

    def hash_hex(self):
        return eth_utils.encode_hex(self.hash)


class BlockBodies(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("bodies", CountableList(Block)),
    ]


class NewBlock(rlp.Serializable):
    def __init__(self, block):
        self.block = block

    @classmethod
    def serializable(cls, obj):
            return True

    @classmethod
    def serialize(cls, obj):
        return Block.serialize(obj.block)

    @classmethod
    def deserialize(cls, serial):
        return cls(block=Block.deserialize(serial))


class TerminalBlockHashes(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("hashes", CountableList(hash32)),
    ]


class GetTerminalBlockHashes(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
    ]

    def __init__(self, reqid=0):
        super().__init__(reqid)


class GetBlocks(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("with_public", big_endian_int),
        ("hashes", CountableList(hash32)),
    ]

    def __init__(self, reqid=0, with_public=0, hashes=[]):
        super().__init__(
            reqid=reqid,
            with_public=with_public,
            hashes=hashes
        )


class Blocks(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("blocks", CountableList(Block)),
    ]


class GetCompactBlocks(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("hashes", CountableList(hash32)),
    ]


class CompactBlock(rlp.Serializable):
    fields = [
        ("block_header", BlockHeader),
        ("nonce", big_endian_int),
        ("tx_short_ids", CountableList(big_endian_int)),
    ]


class GetCompactBlocksResponse(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("compact_blocks", CountableList(CompactBlock)),
        ("blocks", CountableList(Block))
    ]


class GetBlockTxn(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("block_hash", hash32),
        ("indexes", CountableList(big_endian_int)),
    ]


class GetBlockTxnResponse(rlp.Serializable):
    fields = [
        ("reqid", big_endian_int),
        ("block_hash", hash32),
        ("block_txn", CountableList(Transaction))
    ]


class Account(rlp.Serializable):
    fields = [
        ("balance", big_endian_int),
        ("nonce", big_endian_int),
        ("storage_root", hash32),
        ("code_hash", hash32),
    ]


msg_id_dict = {
    Status: STATUS,
    NewBlockHashes: NEW_BLOCK_HASHES,
    Transactions: TRANSACTIONS,
    GetBlockHashes: GET_BLOCK_HASHES,
    BlockHashes: GET_BLOCK_HASHES_RESPONSE,
    GetBlockHeaders: GET_BLOCK_HEADERS,
    BlockHeaders: GET_BLOCK_HEADERS_RESPONSE,
    GetBlockBodies: GET_BLOCK_BODIES,
    BlockBodies: GET_BLOCK_BODIES_RESPONSE,
    NewBlock: NEW_BLOCK,
    TerminalBlockHashes: GET_TERMINAL_BLOCK_HASHES_RESPONSE,
    GetTerminalBlockHashes: GET_TERMINAL_BLOCK_HASHES,
    GetBlocks: GET_BLOCKS,
    Blocks: GET_BLOCKS_RESPONSE,
    GetCompactBlocks: GET_CMPCT_BLOCKS,
    GetCompactBlocksResponse: GET_CMPCT_BLOCKS_RESPONSE,
    GetBlockTxn: GET_BLOCK_TXN,
    GetBlockTxnResponse: GET_BLOCK_TXN_RESPONSE,
    GetBlockHashesByEpoch: GET_BLOCK_HASHES_BY_EPOCH,
}

msg_class_dict = {}
for c in msg_id_dict:
    msg_class_dict[msg_id_dict[c]] = c


def get_msg_id(msg):
    c = msg.__class__
    if c in msg_id_dict:
        return msg_id_dict[c]
    else:
        return None


def get_msg_class(msg):
    if msg in msg_class_dict:
        return msg_class_dict[msg]
    else:
        return None


def is_sequence(s):
    return isinstance(s, list) or isinstance(s, tuple)
