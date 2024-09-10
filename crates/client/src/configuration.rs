// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{collections::BTreeMap, convert::TryInto, path::PathBuf, sync::Arc};

use lazy_static::*;
use parking_lot::RwLock;
use rand::Rng;

use cfx_addr::{cfx_addr_decode, Network};
use cfx_executor::{machine::Machine, spec::CommonParams};
use cfx_internal_common::{
    ChainIdParams, ChainIdParamsInner, ChainIdParamsOneChainInner,
};
use cfx_parameters::{
    block::DEFAULT_TARGET_BLOCK_GAS_LIMIT, tx_pool::TXPOOL_DEFAULT_NONCE_BITS,
};
use cfx_storage::{
    defaults::DEFAULT_DEBUG_SNAPSHOT_CHECKER_THREADS, storage_dir,
    ConsensusParam, ProvideExtraSnapshotSyncConfig, StorageConfiguration,
};
use cfx_types::{
    parse_hex_string, Address, AllChainID, Space, SpaceMap, H256, U256,
};
use cfxcore::{
    block_data_manager::{DataManagerConfiguration, DbType},
    block_parameters::*,
    cache_config::{
        DEFAULT_INVALID_BLOCK_HASH_CACHE_SIZE_IN_COUNT,
        DEFAULT_LEDGER_CACHE_SIZE,
        DEFAULT_TARGET_DIFFICULTIES_CACHE_SIZE_IN_COUNT,
    },
    consensus::{
        consensus_inner::consensus_executor::ConsensusExecutionConfiguration,
        pos_handler::PosVerifier, ConsensusConfig, ConsensusInnerConfig,
    },
    consensus_internal_parameters::*,
    consensus_parameters::*,
    light_protocol::LightNodeConfiguration,
    sync::{ProtocolConfiguration, StateSyncConfiguration, SyncGraphConfig},
    sync_parameters::*,
    transaction_pool::TxPoolConfig,
    NodeType,
};
use diem_types::term_state::{
    pos_state_config::PosStateConfig, IN_QUEUE_LOCKED_VIEWS,
    OUT_QUEUE_LOCKED_VIEWS, ROUND_PER_TERM, TERM_ELECTED_SIZE, TERM_MAX_SIZE,
};
use metrics::MetricsConfiguration;
use network::DiscoveryConfiguration;
use primitives::block_header::CIP112_TRANSITION_HEIGHT;
use txgen::TransactionGeneratorConfig;

use crate::rpc::{
    impls::RpcImplConfiguration, rpc_apis::ApiSet, HttpConfiguration,
    TcpConfiguration, WsConfiguration,
};

lazy_static! {
    pub static ref CHAIN_ID: RwLock<Option<ChainIdParams>> = Default::default();
}
const BLOCK_DB_DIR_NAME: &str = "blockchain_db";
const NET_CONFIG_DB_DIR_NAME: &str = "net_config";

// usage:
// ```
// build_config! {
//     {
//         (name, (type), default_value)
//         ...
//     }
//     {
//         (name, (type), default_value, converter)
//     }
// }
// ```
// `converter` is a function used to convert a provided String to `Result<type,
// String>`. For each entry, field `name` of type `type` will be created in
// `RawConfiguration`, and it will be assigned to the value passed through
// commandline argument or configuration file. Commandline argument will
// override the configuration file if the parameter is given in both.
build_config! {
    {
        // Configs are grouped by section. Within one section configs should
        // be kept in alphabetical order for the sake of indexing and maintenance.
        //
        // Some preset configurations.
        //
        // For both `test` and `dev` modes, we will
        //     * Set initial difficulty to 4
        //     * Allow calling test and debug rpc from public port
        //
        // `test` mode is for Conflux testing and debugging, we will
        //     * Add latency to peer connections
        //     * Skip handshake encryption check
        //     * Skip header timestamp verification
        //     * Handle NewBlockHash even in catch-up mode
        //     * Allow data propagation test
        //     * Allow setting genesis accounts and generate tx from secrets
        //
        // `dev` mode is for users to run a single node that automatically
        //     generates blocks with fixed intervals
        //     * You are expected to also set `jsonrpc_ws_port`, `jsonrpc_tcp_port`,
        //       and `jsonrpc_http_port` if you want RPC functionalities.
        //     * generate blocks automatically without PoW.
        //     * Skip catch-up mode even there is no peer
        //
        (mode, (Option<String>), None)
        // Development related section.
        (debug_invalid_state_root, (bool), false)
        (debug_invalid_state_root_epoch, (Option<String>), None)
        (debug_dump_dir_invalid_state_root, (String), "./storage_db/debug_dump_invalid_state_root/".to_string())
        // Controls block generation speed.
        // Only effective in `dev` mode
        (dev_block_interval_ms, (Option<u64>), None)
        (dev_pack_tx_immediately, (Option<bool>), None)
        (enable_state_expose, (bool), false)
        (generate_tx, (bool), false)
        (generate_tx_period_us, (Option<u64>), Some(100_000))
        (log_conf, (Option<String>), None)
        (log_file, (Option<String>), None)
        (max_block_size_in_bytes, (usize), MAX_BLOCK_SIZE_IN_BYTES)
        (evm_transaction_block_ratio,(u64),EVM_TRANSACTION_BLOCK_RATIO)
        (evm_transaction_gas_ratio,(u64),EVM_TRANSACTION_GAS_RATIO)
        (metrics_enabled, (bool), false)
        (metrics_influxdb_host, (Option<String>), None)
        (metrics_influxdb_db, (String), "conflux".into())
        (metrics_influxdb_username, (Option<String>), None)
        (metrics_influxdb_password, (Option<String>), None)
        (metrics_influxdb_node, (Option<String>), None)
        (metrics_output_file, (Option<String>), None)
        (metrics_report_interval_ms, (u64), 3_000)
        (rocksdb_disable_wal, (bool), false)
        (txgen_account_count, (usize), 10)

        // Genesis section.
        (adaptive_weight_beta, (u64), ADAPTIVE_WEIGHT_DEFAULT_BETA)
        (anticone_penalty_ratio, (u64), ANTICONE_PENALTY_RATIO)
        (chain_id, (Option<u32>), None)
        (evm_chain_id, (Option<u32>), None)
        (execute_genesis, (bool), true)
        (default_transition_time, (Option<u64>), None)
        // Snapshot Epoch Count is a consensus parameter. This flag overrides
        // the parameter, which only take effect in `dev` mode.
        (dev_snapshot_epoch_count, (u32), SNAPSHOT_EPOCHS_CAPACITY)
        (era_epoch_count, (u64), ERA_DEFAULT_EPOCH_COUNT)
        (heavy_block_difficulty_ratio, (u64), HEAVY_BLOCK_DEFAULT_DIFFICULTY_RATIO)
        (genesis_accounts, (Option<String>), None)
        (genesis_secrets, (Option<String>), None)
        (initial_difficulty, (Option<u64>), None)
        (tanzanite_transition_height, (u64), TANZANITE_HEIGHT)
        (hydra_transition_number, (Option<u64>), None)
        (hydra_transition_height, (Option<u64>), None)
        (dao_vote_transition_number, (Option<u64>), None)
        (dao_vote_transition_height, (Option<u64>), None)
        (cip43_init_end_number, (Option<u64>), None)
        (cip78_patch_transition_number,(Option<u64>),None)
        (cip90_transition_height,(Option<u64>),None)
        (cip90_transition_number,(Option<u64>),None)
        (cip105_transition_number, (Option<u64>), None)
        (sigma_fix_transition_number, (Option<u64>), None)
        (cip107_transition_number, (Option<u64>), None)
        (cip112_transition_height, (Option<u64>), None)
        (cip118_transition_number, (Option<u64>), None)
        (cip119_transition_number, (Option<u64>), None)
        (next_hardfork_transition_number, (Option<u64>), None)
        (next_hardfork_transition_height, (Option<u64>), None)
        (cip1559_transition_height, (Option<u64>), None)
        (cancun_opcodes_transition_number, (Option<u64>), None)
        (referee_bound, (usize), REFEREE_DEFAULT_BOUND)
        (params_dao_vote_period, (u64), DAO_PARAMETER_VOTE_PERIOD)
        (timer_chain_beta, (u64), TIMER_CHAIN_DEFAULT_BETA)
        (timer_chain_block_difficulty_ratio, (u64), TIMER_CHAIN_BLOCK_DEFAULT_DIFFICULTY_RATIO)
        (min_native_base_price, (Option<u64>), None)
        (min_eth_base_price, (Option<u64>), None)
        // FIXME: this is part of spec.
        (transaction_epoch_bound, (u64), TRANSACTION_DEFAULT_EPOCH_BOUND)

        // Mining section.
        (mining_author, (Option<String>), None)
        (mining_type, (Option<String>), None)
        (stratum_listen_address, (String), "127.0.0.1".into())
        (stratum_port, (u16), 32525)
        (stratum_secret, (Option<String>), None)
        (use_octopus_in_test_mode, (bool), false)
        (pow_problem_window_size, (usize), 1)

        // Network section.
        (jsonrpc_local_tcp_port, (Option<u16>), None)
        (jsonrpc_local_http_port, (Option<u16>), None)
        (jsonrpc_local_ws_port, (Option<u16>), None)
        (jsonrpc_ws_port, (Option<u16>), None)
        (jsonrpc_tcp_port, (Option<u16>), None)
        (jsonrpc_http_port, (Option<u16>), None)
        (jsonrpc_http_threads, (Option<usize>), None)
        (jsonrpc_cors, (Option<String>), None)
        (jsonrpc_http_keep_alive, (bool), false)
        (jsonrpc_ws_max_payload_bytes, (usize), 30 * 1024 * 1024)
        (jsonrpc_http_eth_port, (Option<u16>), None)
        (jsonrpc_ws_eth_port, (Option<u16>), None)
        // The network_id, if unset, defaults to the chain_id.
        // Only override the network_id for local experiments,
        // when user would like to keep the existing blockchain data
        // but disconnect from the public network.
        (network_id, (Option<u64>), None)
        (rpc_enable_metrics, (bool), false)
        (tcp_port, (u16), 32323)
        (public_tcp_port, (Option<u16>), None)
        (public_address, (Option<String>), None)
        (udp_port, (Option<u16>), Some(32323))
        (max_estimation_gas_limit, (Option<u64>), None)

        // Network parameters section.
        (blocks_request_timeout_ms, (u64), 20_000)
        (check_request_period_ms, (u64), 1_000)
        (chunk_size_byte, (u64), DEFAULT_CHUNK_SIZE)
        (demote_peer_for_timeout, (bool), false)
        (dev_allow_phase_change_without_peer, (bool), false)
        (egress_queue_capacity, (usize), 256)
        (egress_min_throttle, (usize), 10)
        (egress_max_throttle, (usize), 64)
        (expire_block_gc_period_s, (u64), 900)
        (headers_request_timeout_ms, (u64), 10_000)
        (heartbeat_period_interval_ms, (u64), 30_000)
        (heartbeat_timeout_ms, (u64), 180_000)
        (inflight_pending_tx_index_maintain_timeout_ms, (u64), 30_000)
        (max_allowed_timeout_in_observing_period, (u64), 10)
        (max_chunk_number_in_manifest, (usize), 500)
        (max_downloading_chunks, (usize), 8)
        (max_downloading_chunk_attempts, (usize), 5)
        (max_downloading_manifest_attempts, (usize), 5)
        (max_handshakes, (usize), 64)
        (max_incoming_peers, (usize), 64)
        (max_inflight_request_count, (u64), 64)
        (max_outgoing_peers, (usize), 8)
        (max_outgoing_peers_archive, (Option<usize>), None)
        (max_peers_tx_propagation, (usize), 128)
        (max_unprocessed_block_size_mb, (usize), (128))
        (min_peers_tx_propagation, (usize), 8)
        (min_phase_change_normal_peer_count, (usize), 3)
        (received_tx_index_maintain_timeout_ms, (u64), 300_000)
        (request_block_with_public, (bool), false)
        (send_tx_period_ms, (u64), 1300)
        (snapshot_candidate_request_timeout_ms, (u64), 10_000)
        (snapshot_chunk_request_timeout_ms, (u64), 30_000)
        (snapshot_manifest_request_timeout_ms, (u64), 30_000)
        (sync_expire_block_timeout_s, (u64), 7200)
        (throttling_conf, (Option<String>), None)
        (timeout_observing_period_s, (u64), 600)
        (transaction_request_timeout_ms, (u64), 30_000)
        (tx_maintained_for_peer_timeout_ms, (u64), 600_000)

        // Peer management section.
        (bootnodes, (Option<String>), None)
        (discovery_discover_node_count, (u32), 16)
        (discovery_expire_time_s, (u64), 20)
        (discovery_fast_refresh_timeout_ms, (u64), 10_000)
        (discovery_find_node_timeout_ms, (u64), 2_000)
        (discovery_housekeeping_timeout_ms, (u64), 1_000)
        (discovery_max_nodes_ping, (usize), 32)
        (discovery_ping_timeout_ms, (u64), 2_000)
        (discovery_round_timeout_ms, (u64), 500)
        (discovery_throttling_interval_ms, (u64), 1_000)
        (discovery_throttling_limit_ping, (usize), 20)
        (discovery_throttling_limit_find_nodes, (usize), 10)
        (enable_discovery, (bool), true)
        (netconf_dir, (Option<String>), None)
        (net_key, (Option<String>), None)
        (node_table_timeout_s, (u64), 300)
        (node_table_promotion_timeout_s, (u64), 3 * 24 * 3600)
        (session_ip_limits, (String), "1,8,4,2".into())
        (subnet_quota, (usize), 128)

        // Transaction cache/transaction pool section.
        (tx_cache_index_maintain_timeout_ms, (u64), 300_000)
        (tx_pool_size, (usize), 50_000)
        (tx_pool_min_native_tx_gas_price, (Option<u64>), None)
        (tx_pool_min_eth_tx_gas_price, (Option<u64>), None)
        (tx_pool_nonce_bits, (usize), TXPOOL_DEFAULT_NONCE_BITS)
        (tx_pool_allow_gas_over_half_block, (bool), false)
        (max_packing_batch_gas_limit, (u64), 3_000_000)
        (max_packing_batch_size, (usize), 50)
        (packing_pool_degree, (u8), 4)


        // Storage Section.
        (additional_maintained_snapshot_count, (u32), 1)
        // `None` for `additional_maintained*` means the data is never garbage collected.
        (additional_maintained_block_body_epoch_count, (Option<usize>), None)
        (additional_maintained_execution_result_epoch_count, (Option<usize>), None)
        (additional_maintained_reward_epoch_count, (Option<usize>), None)
        (additional_maintained_trace_epoch_count, (Option<usize>), None)
        (additional_maintained_transaction_index_epoch_count, (Option<usize>), None)
        (block_cache_gc_period_ms, (u64), 5_000)
        (block_db_dir, (Option<String>), None)
        (block_db_type, (String), "rocksdb".to_string())
        (checkpoint_gc_time_in_era_count, (f64), 0.5)
        // The conflux data dir, if unspecified, is the workdir where conflux is started.
        (conflux_data_dir, (String), "./blockchain_data".to_string())
        (enable_single_mpt_storage, (bool), false)
        (ledger_cache_size, (usize), DEFAULT_LEDGER_CACHE_SIZE)
        (invalid_block_hash_cache_size_in_count, (usize), DEFAULT_INVALID_BLOCK_HASH_CACHE_SIZE_IN_COUNT)
        (rocksdb_cache_size, (Option<usize>), Some(128))
        (rocksdb_compaction_profile, (Option<String>), None)
        (storage_delta_mpts_cache_recent_lfu_factor, (f64), cfx_storage::defaults::DEFAULT_DELTA_MPTS_CACHE_RECENT_LFU_FACTOR)
        (storage_delta_mpts_cache_size, (u32), cfx_storage::defaults::DEFAULT_DELTA_MPTS_CACHE_SIZE)
        (storage_delta_mpts_cache_start_size, (u32), cfx_storage::defaults::DEFAULT_DELTA_MPTS_CACHE_START_SIZE)
        (storage_delta_mpts_node_map_vec_size, (u32), cfx_storage::defaults::MAX_CACHED_TRIE_NODES_R_LFU_COUNTER)
        (storage_delta_mpts_slab_idle_size, (u32), cfx_storage::defaults::DEFAULT_DELTA_MPTS_SLAB_IDLE_SIZE)
        (storage_single_mpt_cache_size, (u32), cfx_storage::defaults::DEFAULT_DELTA_MPTS_CACHE_SIZE * 2)
        (storage_single_mpt_cache_start_size, (u32), cfx_storage::defaults::DEFAULT_DELTA_MPTS_CACHE_START_SIZE * 2)
        (storage_single_mpt_slab_idle_size, (u32), cfx_storage::defaults::DEFAULT_DELTA_MPTS_SLAB_IDLE_SIZE * 2)
        (storage_max_open_snapshots, (u16), cfx_storage::defaults::DEFAULT_MAX_OPEN_SNAPSHOTS)
        (storage_max_open_mpt_count, (u32), cfx_storage::defaults::DEFAULT_MAX_OPEN_MPT)
        (strict_tx_index_gc, (bool), true)
        (sync_state_starting_epoch, (Option<u64>), None)
        (sync_state_epoch_gap, (Option<u64>), None)
        (target_difficulties_cache_size_in_count, (usize), DEFAULT_TARGET_DIFFICULTIES_CACHE_SIZE_IN_COUNT)

        // General/Unclassified section.
        (account_provider_refresh_time_ms, (u64), 1000)
        (check_phase_change_period_ms, (u64), 1000)
        (enable_optimistic_execution, (bool), true)
        (future_block_buffer_capacity, (usize), 32768)
        (get_logs_filter_max_limit, (Option<usize>), None)
        (get_logs_filter_max_epoch_range, (Option<u64>), None)
        (get_logs_filter_max_block_number_range, (Option<u64>), None)
        (get_logs_epoch_batch_size, (usize), 32)
        (max_trans_count_received_in_catch_up, (u64), 60_000)
        (persist_tx_index, (bool), false)
        (persist_block_number_index, (bool), true)
        (print_memory_usage_period_s, (Option<u64>), None)
        (target_block_gas_limit, (u64), DEFAULT_TARGET_BLOCK_GAS_LIMIT)
        (executive_trace, (bool), false)
        (check_status_genesis, (bool), true)
        (packing_gas_limit_block_count, (u64), 10)
        (poll_lifetime_in_seconds, (Option<u32>), None)

        // TreeGraph Section.
        (is_consortium, (bool), false)
        (pos_config_path, (Option<String>), Some("./pos_config/pos_config.yaml".to_string()))
        (pos_genesis_pivot_decision, (Option<H256>), None)
        (vrf_proposal_threshold, (U256), U256::from_str("1111111111111100000000000000000000000000000000000000000000000000").unwrap())
        // Deferred epoch count before a confirmed epoch.
        (pos_pivot_decision_defer_epoch_count, (u64), 50)
        (cip113_pivot_decision_defer_epoch_count, (u64), 20)
        (cip113_transition_height, (u64), u64::MAX)
        (pos_reference_enable_height, (u64), u64::MAX)
        (pos_initial_nodes_path, (String), "./pos_config/initial_nodes.json".to_string())
        (pos_private_key_path, (String), "./pos_config/pos_key".to_string())
        (pos_round_per_term, (u64), ROUND_PER_TERM)
        (pos_term_max_size, (usize), TERM_MAX_SIZE)
        (pos_term_elected_size, (usize), TERM_ELECTED_SIZE)
        (pos_in_queue_locked_views, (u64), IN_QUEUE_LOCKED_VIEWS)
        (pos_out_queue_locked_views, (u64), OUT_QUEUE_LOCKED_VIEWS)
        (pos_cip99_transition_view, (u64), u64::MAX)
        (pos_cip99_in_queue_locked_views, (u64), IN_QUEUE_LOCKED_VIEWS)
        (pos_cip99_out_queue_locked_views, (u64), OUT_QUEUE_LOCKED_VIEWS)
        (nonce_limit_transition_view, (u64), u64::MAX)
        (pos_cip136_transition_view, (u64), u64::MAX)
        (pos_cip136_in_queue_locked_views, (u64), IN_QUEUE_LOCKED_VIEWS)
        (pos_cip136_out_queue_locked_views, (u64), OUT_QUEUE_LOCKED_VIEWS)
        (pos_cip136_round_per_term, (u64), ROUND_PER_TERM)
        (dev_pos_private_key_encryption_password, (Option<String>), None)
        (pos_started_as_voter, (bool), true)

        // Light node section
        (ln_epoch_request_batch_size, (Option<usize>), None)
        (ln_epoch_request_timeout_sec, (Option<u64>), None)
        (ln_header_request_batch_size, (Option<usize>), None)
        (ln_header_request_timeout_sec, (Option<u64>), None)
        (ln_max_headers_in_flight, (Option<usize>), None)
        (ln_max_parallel_epochs_to_request, (Option<usize>), None)
        (ln_num_epochs_to_request, (Option<usize>), None)
        (ln_num_waiting_headers_threshold, (Option<usize>), None)
        (keep_snapshot_before_stable_checkpoint, (bool), true)
        (force_recompute_height_during_construct_pivot, (Option<u64>), None)

        // The snapshot database consists of two tables: snapshot_key_value and snapshot_mpt. However, the size of snapshot_mpt is significantly larger than that of snapshot_key_value.
        // When the configuration parameter use_isolated_db_for_mpt_table is set to true, the snapshot_mpt table will be located in a separate database.
        (use_isolated_db_for_mpt_table, (bool), false)
        // The use_isolated_db_for_mpt_table_height parameter is utilized to determine when to enable the use_isolated_db_for_mpt_table option.
        //  None: enabled since the next snapshot
        //  u64: enabled since the specified height
        (use_isolated_db_for_mpt_table_height, (Option<u64>), None)
        // Recover the latest MPT snapshot from the era checkpoint
        (recovery_latest_mpt_snapshot, (bool), false)
        (keep_era_genesis_snapshot, (bool), true)
    }
    {
        // Development related section.
        (
            log_level, (LevelFilter), LevelFilter::Info, |l| {
                match l {
                    "off" => Ok(LevelFilter::Off),
                    "error" => Ok(LevelFilter::Error),
                    "warn" => Ok(LevelFilter::Warn),
                    "info" => Ok(LevelFilter::Info),
                    "debug" => Ok(LevelFilter::Debug),
                    "trace" => Ok(LevelFilter::Trace),
                    _ => Err("Invalid log_level".to_owned()),
                }
            }
        )

        // Genesis Section
        // chain_id_params describes a complex setup where chain id can change over epochs.
        // Usually this is needed to describe forks. This config overrides chain_id.
        (chain_id_params, (Option<ChainIdParamsOneChainInner>), None,
            ChainIdParamsOneChainInner::parse_config_str)

        // Storage section.
        (provide_more_snapshot_for_sync,
            (Vec<ProvideExtraSnapshotSyncConfig>),
            vec![ProvideExtraSnapshotSyncConfig::StableCheckpoint],
            ProvideExtraSnapshotSyncConfig::parse_config_list)
        (node_type, (Option<NodeType>), None, NodeType::from_str)
        (public_rpc_apis, (ApiSet), ApiSet::Safe, ApiSet::from_str)
        (public_evm_rpc_apis, (ApiSet), ApiSet::Evm, ApiSet::from_str)
        (single_mpt_space, (Option<Space>), None, |s| match s {
            "native" => Ok(Space::Native),
            "evm" => Ok(Space::Ethereum),
            _ =>  Err("Invalid single_mpt_space".to_owned()),
        })
    }
}

macro_rules! set_conf {
    ($src: expr; $dst: expr => {$($field: tt),* }) => {
        {
            let number = $src;
            $($dst.$field = number;)*
        }
    };
}
pub struct Configuration {
    pub raw_conf: RawConfiguration,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            raw_conf: Default::default(),
        }
    }
}

impl Configuration {
    pub fn parse(matches: &clap::ArgMatches) -> Result<Configuration, String> {
        let mut config = Configuration::default();
        config.raw_conf = RawConfiguration::parse(matches)?;

        if matches.is_present("archive") {
            config.raw_conf.node_type = Some(NodeType::Archive);
        } else if matches.is_present("full") {
            config.raw_conf.node_type = Some(NodeType::Full);
        } else if matches.is_present("light") {
            config.raw_conf.node_type = Some(NodeType::Light);
        }

        CIP112_TRANSITION_HEIGHT
            .set(config.raw_conf.cip112_transition_height.unwrap_or(u64::MAX))
            .expect("called once");

        Ok(config)
    }

    fn network_id(&self) -> u64 {
        match self.raw_conf.network_id {
            Some(x) => x,
            // If undefined, the network id is set to the native space chain_id
            // at genesis.
            None => {
                self.chain_id_params()
                    .read()
                    .get_chain_id(/* epoch_number = */ 0)
                    .in_native_space() as u64
            }
        }
    }

    pub fn net_config(&self) -> Result<NetworkConfiguration, String> {
        let mut network_config = NetworkConfiguration::new_with_port(
            self.network_id(),
            self.raw_conf.tcp_port,
            self.discovery_protocol(),
        );

        network_config.is_consortium = self.raw_conf.is_consortium;
        network_config.discovery_enabled = self.raw_conf.enable_discovery;
        network_config.boot_nodes = to_bootnodes(&self.raw_conf.bootnodes)
            .map_err(|e| format!("failed to parse bootnodes: {}", e))?;
        network_config.config_path = Some(match &self.raw_conf.netconf_dir {
            Some(dir) => dir.clone(),
            None => Path::new(&self.raw_conf.conflux_data_dir)
                .join(NET_CONFIG_DB_DIR_NAME)
                .into_os_string()
                .into_string()
                .unwrap(),
        });
        network_config.use_secret =
            self.raw_conf.net_key.as_ref().map(|sec_str| {
                parse_hex_string(sec_str)
                    .expect("net_key is not a valid secret string")
            });
        if let Some(addr) = self.raw_conf.public_address.clone() {
            let addr_ip = if let Some(idx) = addr.find(":") {
                warn!("Public address configuration should not contain port! (val = {}). Content after ':' is ignored.", &addr);
                (&addr[0..idx]).to_string()
            } else {
                addr
            };
            let addr_with_port = match self.raw_conf.public_tcp_port {
                Some(port) => addr_ip + ":" + &port.to_string(),
                None => addr_ip + ":" + &self.raw_conf.tcp_port.to_string(),
            };
            network_config.public_address =
                match addr_with_port.to_socket_addrs().map(|mut i| i.next()) {
                    Ok(sock_addr) => sock_addr,
                    Err(_e) => {
                        warn!("public_address in config is invalid");
                        None
                    }
                };
        }
        network_config.node_table_timeout =
            Duration::from_secs(self.raw_conf.node_table_timeout_s);
        network_config.connection_lifetime_for_promotion =
            Duration::from_secs(self.raw_conf.node_table_promotion_timeout_s);
        network_config.test_mode = self.is_test_mode();
        network_config.subnet_quota = self.raw_conf.subnet_quota;
        network_config.session_ip_limit_config =
            self.raw_conf.session_ip_limits.clone().try_into().map_err(
                |e| format!("failed to parse session ip limit config: {}", e),
            )?;
        network_config.fast_discovery_refresh_timeout = Duration::from_millis(
            self.raw_conf.discovery_fast_refresh_timeout_ms,
        );
        network_config.discovery_round_timeout =
            Duration::from_millis(self.raw_conf.discovery_round_timeout_ms);
        network_config.housekeeping_timeout = Duration::from_millis(
            self.raw_conf.discovery_housekeeping_timeout_ms,
        );
        network_config.max_handshakes = self.raw_conf.max_handshakes;
        network_config.max_incoming_peers = self.raw_conf.max_incoming_peers;
        network_config.max_outgoing_peers = self.raw_conf.max_outgoing_peers;
        network_config.max_outgoing_peers_archive =
            self.raw_conf.max_outgoing_peers_archive.unwrap_or(0);
        Ok(network_config)
    }

    pub fn cache_config(&self) -> CacheConfig {
        let mut cache_config = CacheConfig::default();
        cache_config.ledger = self.raw_conf.ledger_cache_size;
        cache_config.invalid_block_hashes_cache_size_in_count =
            self.raw_conf.invalid_block_hash_cache_size_in_count;
        cache_config.target_difficulties_cache_size_in_count =
            self.raw_conf.target_difficulties_cache_size_in_count;
        cache_config
    }

    pub fn db_config(&self) -> (PathBuf, DatabaseConfig) {
        let db_dir: PathBuf = match &self.raw_conf.block_db_dir {
            Some(dir) => dir.into(),
            None => Path::new(&self.raw_conf.conflux_data_dir)
                .join(BLOCK_DB_DIR_NAME),
        };
        if let Err(e) = fs::create_dir_all(&db_dir) {
            panic!("Error creating database directory: {:?}", e);
        }

        let compact_profile =
            match self.raw_conf.rocksdb_compaction_profile.as_ref() {
                Some(p) => db::DatabaseCompactionProfile::from_str(p).unwrap(),
                None => db::DatabaseCompactionProfile::default(),
            };
        let db_config = db::db_config(
            &db_dir,
            self.raw_conf.rocksdb_cache_size.clone(),
            compact_profile,
            NUM_COLUMNS.clone(),
            self.raw_conf.rocksdb_disable_wal,
        );
        (db_dir, db_config)
    }

    pub fn chain_id_params(&self) -> ChainIdParams {
        if CHAIN_ID.read().is_none() {
            let mut to_init = CHAIN_ID.write();
            if to_init.is_none() {
                if let Some(_chain_id_params) = &self.raw_conf.chain_id_params {
                    unreachable!("Upgradable ChainId is not ready.")
                // *to_init = Some(ChainIdParamsInner::new_from_inner(
                //     chain_id_params,
                // ))
                } else {
                    let chain_id = self
                        .raw_conf
                        .chain_id
                        .unwrap_or_else(|| rand::thread_rng().gen());
                    let evm_chain_id =
                        self.raw_conf.evm_chain_id.unwrap_or(chain_id);
                    *to_init = Some(ChainIdParamsInner::new_simple(
                        AllChainID::new(chain_id, evm_chain_id),
                    ));
                }
            }
        }
        CHAIN_ID.read().as_ref().unwrap().clone()
    }

    pub fn consensus_config(&self) -> ConsensusConfig {
        let enable_optimistic_execution = if DEFERRED_STATE_EPOCH_COUNT <= 1 {
            false
        } else {
            self.raw_conf.enable_optimistic_execution
        };
        let mut conf = ConsensusConfig {
            chain_id: self.chain_id_params(),
            inner_conf: ConsensusInnerConfig {
                adaptive_weight_beta: self.raw_conf.adaptive_weight_beta,
                heavy_block_difficulty_ratio: self
                    .raw_conf
                    .heavy_block_difficulty_ratio,
                timer_chain_block_difficulty_ratio: self
                    .raw_conf
                    .timer_chain_block_difficulty_ratio,
                timer_chain_beta: self.raw_conf.timer_chain_beta,
                era_epoch_count: self.raw_conf.era_epoch_count,
                enable_optimistic_execution,
                enable_state_expose: self.raw_conf.enable_state_expose,
                pos_pivot_decision_defer_epoch_count: self.raw_conf.pos_pivot_decision_defer_epoch_count,
                cip113_pivot_decision_defer_epoch_count: self.raw_conf.cip113_pivot_decision_defer_epoch_count,
                cip113_transition_height: self.raw_conf.cip113_transition_height,
                debug_dump_dir_invalid_state_root: if self
                    .raw_conf
                    .debug_invalid_state_root
                {
                    Some(
                        self.raw_conf.debug_dump_dir_invalid_state_root.clone(),
                    )
                } else {
                    None
                },

                debug_invalid_state_root_epoch: match &self
                    .raw_conf
                    .debug_invalid_state_root_epoch
                {
                    Some(epoch_hex) => {
                        Some(H256::from_str(&epoch_hex).expect("debug_invalid_state_root_epoch byte length is incorrect."))
                    }
                    None => None,
                },
                force_recompute_height_during_construct_pivot: self.raw_conf.force_recompute_height_during_construct_pivot,
                recovery_latest_mpt_snapshot: self.raw_conf.recovery_latest_mpt_snapshot,
                use_isolated_db_for_mpt_table: self.raw_conf.use_isolated_db_for_mpt_table,
            },
            bench_mode: false,
            transaction_epoch_bound: self.raw_conf.transaction_epoch_bound,
            referee_bound: self.raw_conf.referee_bound,
            get_logs_epoch_batch_size: self.raw_conf.get_logs_epoch_batch_size,
            get_logs_filter_max_epoch_range: self.raw_conf.get_logs_filter_max_epoch_range,
            get_logs_filter_max_block_number_range: self.raw_conf.get_logs_filter_max_block_number_range,
            get_logs_filter_max_limit: self.raw_conf.get_logs_filter_max_limit,
            sync_state_starting_epoch: self.raw_conf.sync_state_starting_epoch,
            sync_state_epoch_gap: self.raw_conf.sync_state_epoch_gap,
        };
        match self.raw_conf.node_type {
            Some(NodeType::Archive) => {
                if conf.sync_state_starting_epoch.is_none() {
                    conf.sync_state_starting_epoch = Some(0);
                }
            }
            _ => {
                if conf.sync_state_epoch_gap.is_none() {
                    conf.sync_state_epoch_gap =
                        Some(CATCH_UP_EPOCH_LAG_THRESHOLD);
                }
            }
        }
        conf
    }

    pub fn pow_config(&self) -> ProofOfWorkConfig {
        let stratum_secret =
            self.raw_conf.stratum_secret.as_ref().map(|hex_str| {
                parse_hex_string(hex_str)
                    .expect("Stratum secret should be 64-digit hex string")
            });

        ProofOfWorkConfig::new(
            self.is_test_or_dev_mode(),
            self.raw_conf.use_octopus_in_test_mode,
            self.raw_conf.mining_type.as_ref().map_or_else(
                || {
                    // Enable stratum implicitly if `mining_author` is set.
                    if self.raw_conf.mining_author.is_some() {
                        "stratum"
                    } else {
                        "disable"
                    }
                },
                |s| s.as_str(),
            ),
            self.raw_conf.initial_difficulty,
            self.raw_conf.stratum_listen_address.clone(),
            self.raw_conf.stratum_port,
            stratum_secret,
            self.raw_conf.pow_problem_window_size,
            self.common_params().transition_heights.cip86,
        )
    }

    pub fn verification_config(
        &self, machine: Arc<Machine>, pos_verifier: Arc<PosVerifier>,
    ) -> VerificationConfig {
        VerificationConfig::new(
            self.is_test_mode(),
            self.raw_conf.referee_bound,
            self.raw_conf.max_block_size_in_bytes,
            self.raw_conf.transaction_epoch_bound,
            self.raw_conf.tx_pool_nonce_bits,
            machine,
            pos_verifier,
        )
    }

    pub fn tx_gen_config(&self) -> Option<TransactionGeneratorConfig> {
        if self.is_test_or_dev_mode() &&
            // FIXME: this is not a good condition to check.
            self.raw_conf.genesis_secrets.is_some()
        {
            Some(TransactionGeneratorConfig::new(
                self.raw_conf.generate_tx,
                self.raw_conf.generate_tx_period_us.expect("has default"),
                self.raw_conf.txgen_account_count,
            ))
        } else {
            None
        }
    }

    pub fn storage_config(&self, node_type: &NodeType) -> StorageConfiguration {
        let conflux_data_path = Path::new(&self.raw_conf.conflux_data_dir);
        StorageConfiguration {
            additional_maintained_snapshot_count: self
                .raw_conf
                .additional_maintained_snapshot_count,
            consensus_param: ConsensusParam {
                snapshot_epoch_count: if self.is_test_mode() {
                    self.raw_conf.dev_snapshot_epoch_count
                } else {
                    SNAPSHOT_EPOCHS_CAPACITY
                },
                era_epoch_count: self.raw_conf.era_epoch_count,
            },
            debug_snapshot_checker_threads:
                DEFAULT_DEBUG_SNAPSHOT_CHECKER_THREADS,
            delta_mpts_cache_recent_lfu_factor: self
                .raw_conf
                .storage_delta_mpts_cache_recent_lfu_factor,
            delta_mpts_cache_size: self.raw_conf.storage_delta_mpts_cache_size,
            delta_mpts_cache_start_size: self
                .raw_conf
                .storage_delta_mpts_cache_start_size,
            delta_mpts_node_map_vec_size: self
                .raw_conf
                .storage_delta_mpts_node_map_vec_size,
            delta_mpts_slab_idle_size: self
                .raw_conf
                .storage_delta_mpts_slab_idle_size,
            single_mpt_cache_start_size: self
                .raw_conf
                .storage_single_mpt_cache_start_size,
            single_mpt_cache_size: self.raw_conf.storage_single_mpt_cache_size,
            single_mpt_slab_idle_size: self
                .raw_conf
                .storage_single_mpt_slab_idle_size,
            max_open_snapshots: self.raw_conf.storage_max_open_snapshots,
            path_delta_mpts_dir: conflux_data_path
                .join(&*storage_dir::DELTA_MPTS_DIR),
            path_snapshot_dir: conflux_data_path
                .join(&*storage_dir::SNAPSHOT_DIR),
            path_snapshot_info_db: conflux_data_path
                .join(&*storage_dir::SNAPSHOT_INFO_DB_PATH),
            path_storage_dir: conflux_data_path
                .join(&*storage_dir::STORAGE_DIR),
            provide_more_snapshot_for_sync: self
                .raw_conf
                .provide_more_snapshot_for_sync
                .clone(),
            max_open_mpt_count: self.raw_conf.storage_max_open_mpt_count,
            enable_single_mpt_storage: match node_type {
                NodeType::Archive => self.raw_conf.enable_single_mpt_storage,
                _ => {
                    if self.raw_conf.enable_single_mpt_storage {
                        error!("enable_single_mpt_storage is only supported for Archive nodes!")
                    }
                    false
                }
            },
            single_mpt_space: self.raw_conf.single_mpt_space.clone(),
            cip90a: self
                .raw_conf
                .cip90_transition_height
                .unwrap_or(self.raw_conf.hydra_transition_height.unwrap_or(0)),
            keep_snapshot_before_stable_checkpoint: self
                .raw_conf
                .keep_snapshot_before_stable_checkpoint,
            use_isolated_db_for_mpt_table: self
                .raw_conf
                .use_isolated_db_for_mpt_table,
            use_isolated_db_for_mpt_table_height: self
                .raw_conf
                .use_isolated_db_for_mpt_table_height,
            keep_era_genesis_snapshot: self.raw_conf.keep_era_genesis_snapshot,
        }
    }

    pub fn protocol_config(&self) -> ProtocolConfiguration {
        ProtocolConfiguration {
            is_consortium: self.raw_conf.is_consortium,
            send_tx_period: Duration::from_millis(
                self.raw_conf.send_tx_period_ms,
            ),
            check_request_period: Duration::from_millis(
                self.raw_conf.check_request_period_ms,
            ),
            check_phase_change_period: Duration::from_millis(
                self.raw_conf.check_phase_change_period_ms,
            ),
            heartbeat_period_interval: Duration::from_millis(
                self.raw_conf.heartbeat_period_interval_ms,
            ),
            block_cache_gc_period: Duration::from_millis(
                self.raw_conf.block_cache_gc_period_ms,
            ),
            expire_block_gc_period: Duration::from_secs(
                self.raw_conf.expire_block_gc_period_s,
            ),
            headers_request_timeout: Duration::from_millis(
                self.raw_conf.headers_request_timeout_ms,
            ),
            blocks_request_timeout: Duration::from_millis(
                self.raw_conf.blocks_request_timeout_ms,
            ),
            transaction_request_timeout: Duration::from_millis(
                self.raw_conf.transaction_request_timeout_ms,
            ),
            tx_maintained_for_peer_timeout: Duration::from_millis(
                self.raw_conf.tx_maintained_for_peer_timeout_ms,
            ),
            max_inflight_request_count: self
                .raw_conf
                .max_inflight_request_count,
            request_block_with_public: self.raw_conf.request_block_with_public,
            received_tx_index_maintain_timeout: Duration::from_millis(
                self.raw_conf.received_tx_index_maintain_timeout_ms,
            ),
            inflight_pending_tx_index_maintain_timeout: Duration::from_millis(
                self.raw_conf.inflight_pending_tx_index_maintain_timeout_ms,
            ),
            max_trans_count_received_in_catch_up: self
                .raw_conf
                .max_trans_count_received_in_catch_up,
            min_peers_tx_propagation: self.raw_conf.min_peers_tx_propagation,
            max_peers_tx_propagation: self.raw_conf.max_peers_tx_propagation,
            max_downloading_chunks: self.raw_conf.max_downloading_chunks,
            max_downloading_chunk_attempts: self
                .raw_conf
                .max_downloading_chunk_attempts,
            test_mode: self.is_test_mode(),
            dev_mode: self.is_dev_mode(),
            throttling_config_file: self.raw_conf.throttling_conf.clone(),
            snapshot_candidate_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_candidate_request_timeout_ms,
            ),
            snapshot_manifest_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_manifest_request_timeout_ms,
            ),
            snapshot_chunk_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_chunk_request_timeout_ms,
            ),
            chunk_size_byte: self.raw_conf.chunk_size_byte,
            max_chunk_number_in_manifest: self
                .raw_conf
                .max_chunk_number_in_manifest,
            timeout_observing_period_s: self
                .raw_conf
                .timeout_observing_period_s,
            max_allowed_timeout_in_observing_period: self
                .raw_conf
                .max_allowed_timeout_in_observing_period,
            demote_peer_for_timeout: self.raw_conf.demote_peer_for_timeout,
            heartbeat_timeout: Duration::from_millis(
                self.raw_conf.heartbeat_timeout_ms,
            ),
            max_unprocessed_block_size: self
                .raw_conf
                .max_unprocessed_block_size_mb
                * 1_000_000,
            sync_expire_block_timeout: Duration::from_secs(
                self.raw_conf.sync_expire_block_timeout_s,
            ),
            allow_phase_change_without_peer: if self.is_dev_mode() {
                true
            } else {
                self.raw_conf.dev_allow_phase_change_without_peer
            },
            min_phase_change_normal_peer_count: self
                .raw_conf
                .min_phase_change_normal_peer_count,
            pos_genesis_pivot_decision: self
                .raw_conf
                .pos_genesis_pivot_decision
                .expect("set to genesis if none"),
            check_status_genesis: self.raw_conf.check_status_genesis,
            pos_started_as_voter: self.raw_conf.pos_started_as_voter,
        }
    }

    pub fn state_sync_config(&self) -> StateSyncConfiguration {
        StateSyncConfiguration {
            max_downloading_chunks: self.raw_conf.max_downloading_chunks,
            candidate_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_candidate_request_timeout_ms,
            ),
            chunk_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_chunk_request_timeout_ms,
            ),
            manifest_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_manifest_request_timeout_ms,
            ),
            max_downloading_manifest_attempts: self
                .raw_conf
                .max_downloading_manifest_attempts,
        }
    }

    pub fn data_mananger_config(&self) -> DataManagerConfiguration {
        let mut conf = DataManagerConfiguration {
            persist_tx_index: self.raw_conf.persist_tx_index,
            persist_block_number_index: self
                .raw_conf
                .persist_block_number_index,
            tx_cache_index_maintain_timeout: Duration::from_millis(
                self.raw_conf.tx_cache_index_maintain_timeout_ms,
            ),
            db_type: match self.raw_conf.block_db_type.as_str() {
                "rocksdb" => DbType::Rocksdb,
                "sqlite" => DbType::Sqlite,
                _ => panic!("Invalid block_db_type parameter!"),
            },
            additional_maintained_block_body_epoch_count: self
                .raw_conf
                .additional_maintained_block_body_epoch_count,
            additional_maintained_execution_result_epoch_count: self
                .raw_conf
                .additional_maintained_execution_result_epoch_count,
            additional_maintained_reward_epoch_count: self
                .raw_conf
                .additional_maintained_reward_epoch_count,
            additional_maintained_trace_epoch_count: self
                .raw_conf
                .additional_maintained_trace_epoch_count,
            additional_maintained_transaction_index_epoch_count: self
                .raw_conf
                .additional_maintained_transaction_index_epoch_count,
            checkpoint_gc_time_in_epoch_count: (self
                .raw_conf
                .checkpoint_gc_time_in_era_count
                * self.raw_conf.era_epoch_count as f64)
                as usize,
            strict_tx_index_gc: self.raw_conf.strict_tx_index_gc,
        };

        // By default, we do not keep the block data for additional period,
        // but `node_type = "archive"` is a shortcut for keeping all them.
        if !matches!(self.raw_conf.node_type, Some(NodeType::Archive)) {
            if conf.additional_maintained_block_body_epoch_count.is_none() {
                conf.additional_maintained_block_body_epoch_count = Some(0);
            }
            if conf
                .additional_maintained_execution_result_epoch_count
                .is_none()
            {
                conf.additional_maintained_execution_result_epoch_count =
                    Some(0);
            }
            if conf
                .additional_maintained_transaction_index_epoch_count
                .is_none()
            {
                conf.additional_maintained_transaction_index_epoch_count =
                    Some(0);
            }
            if conf.additional_maintained_reward_epoch_count.is_none() {
                conf.additional_maintained_reward_epoch_count = Some(0);
            }
            if conf.additional_maintained_trace_epoch_count.is_none() {
                conf.additional_maintained_trace_epoch_count = Some(0);
            }
        }
        if conf.additional_maintained_transaction_index_epoch_count != Some(0) {
            conf.persist_tx_index = true;
        }
        conf
    }

    pub fn sync_graph_config(&self) -> SyncGraphConfig {
        SyncGraphConfig {
            future_block_buffer_capacity: self
                .raw_conf
                .future_block_buffer_capacity,
            enable_state_expose: self.raw_conf.enable_state_expose,
            is_consortium: self.raw_conf.is_consortium,
        }
    }

    pub fn metrics_config(&self) -> MetricsConfiguration {
        MetricsConfiguration {
            enabled: self.raw_conf.metrics_enabled,
            report_interval: Duration::from_millis(
                self.raw_conf.metrics_report_interval_ms,
            ),
            file_report_output: self.raw_conf.metrics_output_file.clone(),
            influxdb_report_host: self.raw_conf.metrics_influxdb_host.clone(),
            influxdb_report_db: self.raw_conf.metrics_influxdb_db.clone(),
            influxdb_report_username: self
                .raw_conf
                .metrics_influxdb_username
                .clone(),
            influxdb_report_password: self
                .raw_conf
                .metrics_influxdb_password
                .clone(),
            influxdb_report_node: self.raw_conf.metrics_influxdb_node.clone(),
        }
    }

    pub fn txpool_config(&self) -> TxPoolConfig {
        let (min_native_tx_price_default, min_eth_tx_price_default) =
            if self.is_test_or_dev_mode() {
                (1, 1)
            } else {
                (ONE_GDRIP_IN_DRIP, 20 * ONE_GDRIP_IN_DRIP)
            };
        TxPoolConfig {
            capacity: self.raw_conf.tx_pool_size,
            half_block_gas_limit: RwLock::new(U256::from(
                DEFAULT_TARGET_BLOCK_GAS_LIMIT / 2,
            )),
            min_native_tx_price: self
                .raw_conf
                .tx_pool_min_native_tx_gas_price
                .unwrap_or(min_native_tx_price_default),
            allow_gas_over_half_block: self
                .raw_conf
                .tx_pool_allow_gas_over_half_block,
            target_block_gas_limit: self.raw_conf.target_block_gas_limit,
            min_eth_tx_price: self
                .raw_conf
                .tx_pool_min_eth_tx_gas_price
                .unwrap_or(min_eth_tx_price_default),
            max_packing_batch_gas_limit: self
                .raw_conf
                .max_packing_batch_gas_limit,
            max_packing_batch_size: self.raw_conf.max_packing_batch_size,
            packing_pool_degree: self.raw_conf.packing_pool_degree,
        }
    }

    pub fn rpc_impl_config(&self) -> RpcImplConfiguration {
        RpcImplConfiguration {
            get_logs_filter_max_limit: self.raw_conf.get_logs_filter_max_limit,
            dev_pack_tx_immediately: self
                .raw_conf
                .dev_pack_tx_immediately
                .unwrap_or_else(|| {
                    self.is_dev_mode()
                        && self.raw_conf.dev_block_interval_ms.is_none()
                }),
            max_payload_bytes: self.raw_conf.jsonrpc_ws_max_payload_bytes,
            enable_metrics: self.raw_conf.rpc_enable_metrics,
            poll_lifetime_in_seconds: self.raw_conf.poll_lifetime_in_seconds,
            max_estimation_gas_limit: self
                .raw_conf
                .max_estimation_gas_limit
                .map(U256::from),
        }
    }

    pub fn local_http_config(&self) -> HttpConfiguration {
        HttpConfiguration::new(
            Some((127, 0, 0, 1)),
            self.raw_conf.jsonrpc_local_http_port,
            self.raw_conf.jsonrpc_cors.clone(),
            self.raw_conf.jsonrpc_http_keep_alive,
            self.raw_conf.jsonrpc_http_threads,
        )
    }

    pub fn http_config(&self) -> HttpConfiguration {
        HttpConfiguration::new(
            None,
            self.raw_conf.jsonrpc_http_port,
            self.raw_conf.jsonrpc_cors.clone(),
            self.raw_conf.jsonrpc_http_keep_alive,
            self.raw_conf.jsonrpc_http_threads,
        )
    }

    pub fn eth_http_config(&self) -> HttpConfiguration {
        HttpConfiguration::new(
            None,
            self.raw_conf.jsonrpc_http_eth_port,
            self.raw_conf.jsonrpc_cors.clone(),
            self.raw_conf.jsonrpc_http_keep_alive,
            self.raw_conf.jsonrpc_http_threads,
        )
    }

    pub fn eth_ws_config(&self) -> WsConfiguration {
        WsConfiguration::new(
            None,
            self.raw_conf.jsonrpc_ws_eth_port,
            self.raw_conf.jsonrpc_ws_max_payload_bytes,
        )
    }

    pub fn local_tcp_config(&self) -> TcpConfiguration {
        TcpConfiguration::new(
            Some((127, 0, 0, 1)),
            self.raw_conf.jsonrpc_local_tcp_port,
        )
    }

    pub fn tcp_config(&self) -> TcpConfiguration {
        TcpConfiguration::new(None, self.raw_conf.jsonrpc_tcp_port)
    }

    pub fn local_ws_config(&self) -> WsConfiguration {
        WsConfiguration::new(
            Some((127, 0, 0, 1)),
            self.raw_conf.jsonrpc_local_ws_port,
            self.raw_conf.jsonrpc_ws_max_payload_bytes,
        )
    }

    pub fn ws_config(&self) -> WsConfiguration {
        WsConfiguration::new(
            None,
            self.raw_conf.jsonrpc_ws_port,
            self.raw_conf.jsonrpc_ws_max_payload_bytes,
        )
    }

    pub fn execution_config(&self) -> ConsensusExecutionConfiguration {
        ConsensusExecutionConfiguration {
            executive_trace: self.raw_conf.executive_trace,
        }
    }

    pub fn discovery_protocol(&self) -> DiscoveryConfiguration {
        DiscoveryConfiguration {
            discover_node_count: self.raw_conf.discovery_discover_node_count,
            expire_time: Duration::from_secs(
                self.raw_conf.discovery_expire_time_s,
            ),
            find_node_timeout: Duration::from_millis(
                self.raw_conf.discovery_find_node_timeout_ms,
            ),
            max_nodes_ping: self.raw_conf.discovery_max_nodes_ping,
            ping_timeout: Duration::from_millis(
                self.raw_conf.discovery_ping_timeout_ms,
            ),
            throttling_interval: Duration::from_millis(
                self.raw_conf.discovery_throttling_interval_ms,
            ),
            throttling_limit_ping: self
                .raw_conf
                .discovery_throttling_limit_ping,
            throttling_limit_find_nodes: self
                .raw_conf
                .discovery_throttling_limit_find_nodes,
        }
    }

    pub fn is_test_mode(&self) -> bool {
        match self.raw_conf.mode.as_ref().map(|s| s.as_str()) {
            Some("test") => true,
            _ => false,
        }
    }

    pub fn is_dev_mode(&self) -> bool {
        match self.raw_conf.mode.as_ref().map(|s| s.as_str()) {
            Some("dev") => true,
            _ => false,
        }
    }

    pub fn is_test_or_dev_mode(&self) -> bool {
        match self.raw_conf.mode.as_ref().map(|s| s.as_str()) {
            Some("dev") | Some("test") => true,
            _ => false,
        }
    }

    pub fn is_consortium(&self) -> bool { self.raw_conf.is_consortium }

    pub fn light_node_config(&self) -> LightNodeConfiguration {
        LightNodeConfiguration {
            epoch_request_batch_size: self.raw_conf.ln_epoch_request_batch_size,
            epoch_request_timeout: self
                .raw_conf
                .ln_epoch_request_timeout_sec
                .map(Duration::from_secs),
            header_request_batch_size: self
                .raw_conf
                .ln_header_request_batch_size,
            header_request_timeout: self
                .raw_conf
                .ln_header_request_timeout_sec
                .map(Duration::from_secs),
            max_headers_in_flight: self.raw_conf.ln_max_headers_in_flight,
            max_parallel_epochs_to_request: self
                .raw_conf
                .ln_max_parallel_epochs_to_request,
            num_epochs_to_request: self.raw_conf.ln_num_epochs_to_request,
            num_waiting_headers_threshold: self
                .raw_conf
                .ln_num_waiting_headers_threshold,
        }
    }

    pub fn common_params(&self) -> CommonParams {
        let mut params = CommonParams::default();

        if self.is_test_or_dev_mode() {
            params.early_set_internal_contracts_states = true;
        }

        let non_test_default = SpaceMap::new(
            INITIAL_1559_CORE_BASE_PRICE,
            INITIAL_1559_ETH_BASE_PRICE,
        );
        let test_default = SpaceMap::new(1u64, 1);
        let config = SpaceMap::new(
            self.raw_conf.min_native_base_price,
            self.raw_conf.min_eth_base_price,
        );
        let base_price = SpaceMap::zip3(non_test_default, test_default, config)
            .map_all(|(non_test, test, config)| {
                if let Some(x) = config {
                    x
                } else if self.is_test_or_dev_mode() {
                    test
                } else {
                    non_test
                }
            });
        params.min_base_price = base_price.map_all(U256::from);

        params.chain_id = self.chain_id_params();
        params.anticone_penalty_ratio = self.raw_conf.anticone_penalty_ratio;
        params.evm_transaction_block_ratio =
            self.raw_conf.evm_transaction_block_ratio;
        params.evm_transaction_gas_ratio =
            self.raw_conf.evm_transaction_gas_ratio;

        params.params_dao_vote_period = self.raw_conf.params_dao_vote_period;

        self.set_cips(&mut params);

        params
    }

    pub fn node_type(&self) -> NodeType {
        self.raw_conf.node_type.unwrap_or(NodeType::Full)
    }

    pub fn pos_state_config(&self) -> PosStateConfig {
        // The current implementation requires the round number to be an even
        // number.
        assert_eq!(self.raw_conf.pos_round_per_term % 2, 0);
        PosStateConfig::new(
            self.raw_conf.pos_round_per_term,
            self.raw_conf.pos_term_max_size,
            self.raw_conf.pos_term_elected_size,
            self.raw_conf.pos_in_queue_locked_views,
            self.raw_conf.pos_out_queue_locked_views,
            self.raw_conf.pos_cip99_transition_view,
            self.raw_conf.pos_cip99_in_queue_locked_views,
            self.raw_conf.pos_cip99_out_queue_locked_views,
            self.raw_conf.nonce_limit_transition_view,
            20_000, // 2 * 10^7 CFX
            self.raw_conf.pos_cip136_transition_view,
            self.raw_conf.pos_cip136_in_queue_locked_views,
            self.raw_conf.pos_cip136_out_queue_locked_views,
            self.raw_conf.pos_cip136_round_per_term,
        )
    }

    fn set_cips(&self, params: &mut CommonParams) {
        let default_transition_time =
            if let Some(num) = self.raw_conf.default_transition_time {
                num
            } else if self.is_test_or_dev_mode() {
                0u64
            } else {
                u64::MAX
            };

        // This is to set the default transition time for the CIPs that cannot
        // be enabled in the genesis.
        let non_genesis_default_transition_time =
            match self.raw_conf.default_transition_time {
                Some(num) if num > 0 => num,
                _ => {
                    if self.is_test_or_dev_mode() {
                        1u64
                    } else {
                        u64::MAX
                    }
                }
            };

        //
        // Tanzanite hardfork
        //
        params.transition_heights.cip40 =
            self.raw_conf.tanzanite_transition_height;
        let mut base_block_rewards = BTreeMap::new();
        base_block_rewards.insert(0, INITIAL_BASE_MINING_REWARD_IN_UCFX.into());
        base_block_rewards.insert(
            params.transition_heights.cip40,
            MINING_REWARD_TANZANITE_IN_UCFX.into(),
        );
        params.base_block_rewards = base_block_rewards;

        //
        // Hydra hardfork (V2.0)
        //
        set_conf!(
            self.raw_conf.hydra_transition_number.unwrap_or(default_transition_time);
            params.transition_numbers => { cip43a, cip64, cip71, cip78a, cip92 }
        );
        set_conf!(
            self.raw_conf.hydra_transition_height.unwrap_or(default_transition_time);
            params.transition_heights => { cip76, cip86 }
        );
        params.transition_numbers.cip43b =
            self.raw_conf.cip43_init_end_number.unwrap_or(
                if self.is_test_or_dev_mode() {
                    u64::MAX
                } else {
                    params.transition_numbers.cip43a
                },
            );
        params.transition_numbers.cip62 = if self.is_test_or_dev_mode() {
            0u64
        } else {
            BN128_ENABLE_NUMBER
        };
        params.transition_numbers.cip78b = self
            .raw_conf
            .cip78_patch_transition_number
            .unwrap_or(params.transition_numbers.cip78a);
        params.transition_heights.cip90a = self
            .raw_conf
            .cip90_transition_height
            .or(self.raw_conf.hydra_transition_height)
            .unwrap_or(default_transition_time);
        params.transition_numbers.cip90b = self
            .raw_conf
            .cip90_transition_number
            .or(self.raw_conf.hydra_transition_number)
            .unwrap_or(default_transition_time);

        //
        // DAO vote hardfork (V2.1)
        //
        set_conf!(
            self.raw_conf.dao_vote_transition_number.unwrap_or(default_transition_time);
            params.transition_numbers => { cip97, cip98 }
        );
        params.transition_numbers.cip94n = self
            .raw_conf
            .dao_vote_transition_number
            .unwrap_or(non_genesis_default_transition_time);
        params.transition_heights.cip94h = self
            .raw_conf
            .dao_vote_transition_height
            .unwrap_or(non_genesis_default_transition_time);
        params.transition_numbers.cip105 = self
            .raw_conf
            .cip105_transition_number
            .or(self.raw_conf.dao_vote_transition_number)
            .unwrap_or(default_transition_time);

        //
        // Sigma protocol fix hardfork (V2.2)
        //
        params.transition_numbers.cip_sigma_fix = self
            .raw_conf
            .sigma_fix_transition_number
            .unwrap_or(default_transition_time);

        //
        // Burn collateral hardfork (V2.3)
        //
        params.transition_numbers.cip107 = self
            .raw_conf
            .cip107_transition_number
            .unwrap_or(default_transition_time);
        params.transition_heights.cip112 =
            *CIP112_TRANSITION_HEIGHT.get().expect("initialized");
        params.transition_numbers.cip118 = self
            .raw_conf
            .cip118_transition_number
            .unwrap_or(default_transition_time);
        params.transition_numbers.cip119 = self
            .raw_conf
            .cip119_transition_number
            .unwrap_or(default_transition_time);

        //
        // 1559 hardfork (V2.4)
        //
        set_conf!(
            self.raw_conf.next_hardfork_transition_number.unwrap_or(default_transition_time);
            params.transition_numbers => { cip131, cip132, cip133b, cip137, cip144, cip145 }
        );
        set_conf!(
            self.raw_conf.next_hardfork_transition_height.unwrap_or(default_transition_time);
            params.transition_heights => { cip130, cip133e }
        );
        // TODO: disable 1559 test during dev
        params.transition_heights.cip1559 = self
            .raw_conf
            .cip1559_transition_height
            .or(self.raw_conf.next_hardfork_transition_height)
            .unwrap_or(non_genesis_default_transition_time);
        params.transition_numbers.cancun_opcodes = self
            .raw_conf
            .cancun_opcodes_transition_number
            .or(self.raw_conf.next_hardfork_transition_number)
            .unwrap_or(default_transition_time);

        if params.transition_heights.cip1559
            < self.raw_conf.pos_reference_enable_height
        {
            panic!("1559 can not be activated earlier than pos reference: 1559 (epoch {}), pos (epoch {})", params.transition_heights.cip1559, self.raw_conf.pos_reference_enable_height);
        }
    }
}

/// Validates and formats bootnodes option.
pub fn to_bootnodes(bootnodes: &Option<String>) -> Result<Vec<String>, String> {
    match *bootnodes {
        Some(ref x) if !x.is_empty() => x
            .split(',')
            // ignore empty strings
            .filter(|s| !s.is_empty())
            .map(|s| match validate_node_url(s).map(Into::into) {
                None => Ok(s.to_owned()),
                Some(ErrorKind::AddressResolve(_)) => Err(format!(
                    "Failed to resolve hostname of a boot node: {}",
                    s
                )),
                Some(e) => Err(format!(
                    "Invalid node address format given for a boot node: {} err={:?}",
                    s, e
                )),
            })
            .collect(),
        Some(_) => Ok(vec![]),
        None => Ok(vec![]),
    }
}

pub fn parse_config_address_string(
    addr: &str, network: &Network,
) -> Result<Address, String> {
    let base32_err = match cfx_addr_decode(addr) {
        Ok(address) => {
            return if address.network != *network {
                Err(format!(
                    "address in configuration has unmatching network id: expected network={},\
                     address.network={}",
                    network,
                    address.network
                ))
            } else {
                address
                    .hex_address
                    .ok_or("decoded address has wrong byte length".into())
            };
        }
        Err(e) => e,
    };
    let hex_err = match parse_hex_string(addr) {
        Ok(address) => return Ok(address),
        Err(e) => e,
    };
    // An address from config must be valid.
    Err(format!("Address from configuration should be a valid base32 address or a 40-digit hex string!
            base32_err={:?}
            hex_err={:?}",
                base32_err, hex_err))
}

#[cfg(test)]
mod tests {
    use cfx_addr::Network;

    use crate::configuration::parse_config_address_string;

    #[test]
    fn test_config_address_string() {
        let addr = parse_config_address_string(
            "0x1a2f80341409639ea6a35bbcab8299066109aa55",
            &Network::Main,
        )
        .unwrap();
        // Allow omitting the leading "0x" prefix.
        assert_eq!(
            addr,
            parse_config_address_string(
                "1a2f80341409639ea6a35bbcab8299066109aa55",
                &Network::Main,
            )
            .unwrap()
        );
        // Allow CIP-37 base32 address.
        assert_eq!(
            addr,
            parse_config_address_string(
                "cfx:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg",
                &Network::Main,
            )
            .unwrap()
        );
        // Allow optional fields in CIP-37 base32 address.
        assert_eq!(
            addr,
            parse_config_address_string(
                "cfx:type.user:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg",
                &Network::Main,
            )
            .unwrap()
        );
    }
}
