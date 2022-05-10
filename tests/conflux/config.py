from . import trie
from eth_utils import decode_hex

DEFAULT_PY_TEST_CHAIN_ID = 10

default_config = dict(
    GENESIS_DIFFICULTY=0,
    GENESIS_PREVHASH=decode_hex("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), # KECCAK EMPTY, hash of the empty bytes string.
    GENESIS_COINBASE=b'\x10' * 20,
    GENESIS_PRI_KEY=decode_hex("46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"),
    GENESIS_PRI_KEY_2=decode_hex("9a6d3ba2b0c7514b16a006ee605055d71b9edfad183aeb2d9790e9d4ccced471"),
    TOTAL_COIN= 5 * 10**9 * 10**18 * 10**6,
    GENESIS_STATE_ROOT=decode_hex("0x3a5ce6e6d182784af05d273b069d2a023e93c43a0281a57810d2f4b63a6ad6b1"),
    GENESIS_RECEIPTS_ROOT=trie.EMPTY_EPOCH_RECEIPT_ROOT_BY_NUMBER_OF_BLOCKS[0],
    GENESIS_LOGS_BLOOM_HASH=decode_hex("0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5"), # KECCAK_EMPTY_BLOOM    ~ keccak(b'\0' * 256)
    GENESIS_TRANSACTION_ROOT=decode_hex("0x8208dfdbb409f7a3e41386a8eaaa6412ad4df158fc04a09b499c1a004b53d469"),
    GENESIS_AUTHOR=decode_hex("1949000000000000000000000000000000001001"),
    GENESIS_GAS_LIMIT=30_000_000,
    MAX_BLOCK_SIZE_IN_BYTES=200 * 1024,
    POS_GENESIS_BLOCK=b'\x00' * 32,
    POS_VOTE_COUNT=1000,
)

default_conflux_conf = dict(
    chain_id = DEFAULT_PY_TEST_CHAIN_ID,
    db_cache_size = 128,
    ledger_cache_size = 1024,
    storage_delta_mpts_cache_size = 20_000_000,
    storage_delta_mpts_cache_start_size = 2_000_000,
    storage_delta_mpts_slab_idle_size = 2_000_000,
    tx_pool_size = 500_000,
    persist_tx_index = "true",
    persist_block_number_index = "true",
)

production_conf = default_conflux_conf

small_local_test_conf = dict(
    chain_id = DEFAULT_PY_TEST_CHAIN_ID,
    check_phase_change_period_ms = 100,
    enable_discovery = "false",
    log_file = "'./conflux.log'",
    log_level = '"debug"',
    metrics_output_file = "'./metrics.log'",
    metrics_enabled = "true",
    mode = '"test"',
    session_ip_limits = "'0,0,0,0'",
    mining_type = "'disable'",
    storage_delta_mpts_cache_size = 200_000,
    storage_delta_mpts_cache_start_size = 200_000,
    storage_delta_mpts_slab_idle_size = 2_000_000,
    subnet_quota = 0,
    persist_tx_index = "true",
    persist_block_number_index = "true",
    execute_genesis = "false",
    dev_allow_phase_change_without_peer = "true",
    check_status_genesis = "false",
    pos_reference_enable_height = 0,
    hydra_transition_height = 0,
    hydra_transition_number = 0,
    cip43_init_end_number = 2 ** 32 - 1,
    min_phase_change_normal_peer_count = 1,
    dao_vote_transition_number = 2**31,
    dao_vote_transition_height = 2**31,
    enable_single_mpt_storage = "true",
    rpc_enable_metrics = "true",
)
