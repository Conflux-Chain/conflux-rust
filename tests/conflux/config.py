from . import trie
from eth_utils import decode_hex

default_config = dict(
    GENESIS_DIFFICULTY=0,
    GENESIS_PREVHASH=decode_hex("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), # KECCAK EMPTY, hash of the empty bytes string.
    GENESIS_COINBASE=b'\x00' * 20,
    GENESIS_PRI_KEY=decode_hex("46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"),
    TOTAL_COIN= 5 * 10**9 * 10**18 * 10**6,
    GENESIS_STATE_ROOT=decode_hex("0xe98b48cfa78d07deda2969f9cbf32bd1745609af9a5b31b15e67c149def9c047"),
    GENESIS_RECEIPTS_ROOT=decode_hex("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),   # KECCAK_EMPTY_LIST_RLP ~ keccak(rlp([]))
    GENESIS_LOGS_BLOOM_HASH=decode_hex("0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5"), # KECCAK_EMPTY_BLOOM    ~ keccak(b'\0' * 256)
    GENESIS_AUTHOR=decode_hex("0x0000000000000000000000000000000000000011"),
)
