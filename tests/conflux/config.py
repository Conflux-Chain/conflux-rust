from . import trie
from eth_utils import decode_hex

DEFAULT_PY_TEST_CHAIN_ID = 10

default_config = dict(
    GENESIS_DIFFICULTY=0,
    GENESIS_PREVHASH=decode_hex("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), # KECCAK EMPTY, hash of the empty bytes string.
    GENESIS_COINBASE=b'\x10' * 20,
    GENESIS_PRI_KEY=decode_hex("46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"),
    TOTAL_COIN= 5 * 10**9 * 10**18 * 10**6,
    GENESIS_STATE_ROOT=decode_hex("0xd8b87cc5cf36cd3f2b655446bbaec331a63b80dfabececc379bf197e56949e39"),
    GENESIS_RECEIPTS_ROOT=decode_hex("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),   # KECCAK_EMPTY_LIST_RLP ~ keccak(rlp([]))
    GENESIS_LOGS_BLOOM_HASH=decode_hex("0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5"), # KECCAK_EMPTY_BLOOM    ~ keccak(b'\0' * 256)
    GENESIS_AUTHOR=decode_hex("0x0000000000000000000000000000000000000020"),
    GENESIS_GAS_LIMIT=30_000_000,
    MAX_BLOCK_SIZE_IN_BYTES=200 * 1024,
)

default_conflux_conf = dict(
    chain_id = DEFAULT_PY_TEST_CHAIN_ID,
    db_cache_size = 128,
    ledger_cache_size = 1024,
    storage_delta_mpts_cache_size = 20_000_000,
    storage_delta_mpts_cache_start_size = 2_000_000,
    storage_delta_mpts_slab_idle_size = 2_000_000,
    tx_pool_size = 500_000,
)

production_conf = default_conflux_conf

small_local_test_conf = dict(
    chain_id = DEFAULT_PY_TEST_CHAIN_ID,
    enable_discovery = "false",
    log_file = "'./conflux.log'",
    log_level = '"debug"',
    metrics_output_file = "'./metrics.log'",
    metrics_enabled = "true",
    mode = '"test"',
    session_ip_limits = "'0,0,0,0'",
    start_mining = "false",
    storage_delta_mpts_cache_size = 200_000,
    storage_delta_mpts_cache_start_size = 200_000,
    storage_delta_mpts_slab_idle_size = 2_000_000,
    subnet_quota = 0,
)
