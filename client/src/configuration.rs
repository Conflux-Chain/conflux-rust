// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::impls::cfx::RpcImplConfiguration;
use cfx_types::H256;
use cfxcore::{
    block_data_manager::{DataManagerConfiguration, DbType},
    block_parameters::*,
    cache_config::DEFAULT_LEDGER_CACHE_SIZE,
    consensus::{
        consensus_inner::consensus_executor::ConsensusExecutionConfiguration,
        ConsensusConfig, ConsensusInnerConfig,
    },
    consensus_internal_parameters::*,
    consensus_parameters::*,
    storage::{
        self, defaults::DEFAULT_DEBUG_SNAPSHOT_CHECKER_THREADS, ConsensusParam,
        StorageConfiguration,
    },
    sync::{ProtocolConfiguration, StateSyncConfiguration, SyncGraphConfig},
    sync_parameters::*,
    transaction_pool::TxPoolConfig,
};
use metrics::MetricsConfiguration;
use std::convert::TryInto;
use txgen::TransactionGeneratorConfig;

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
        //     * Open port 12536 for tcp rpc if `jsonrpc_tcp_port` is not provided.
        //     * Open port 12537 for http rpc if `jsonrpc_http_port` is not provided.
        //     * generate blocks automatically without PoW if `start_mining` is false
        //     * Skip catch-up mode even there is no peer
        //
        (mode, (Option<String>), None)
        // Development related section.
        (data_propagate_enabled, (bool), false)
        (data_propagate_interval_ms, (u64), 1_000)
        (data_propagate_size, (usize), 1_000)
        (debug_dump_dir_invalid_state_root, (String), "./storage/debug_dump_invalid_state_root/".to_string())
        // Controls block generation speed.
        // Only effective in `dev` mode and `start_mining` is false
        (dev_block_interval_ms, (u64), 250)
        (enable_state_expose, (bool), false)
        (generate_tx, (bool), false)
        (generate_tx_period_us, (Option<u64>), Some(100_000))
        (log_conf, (Option<String>), None)
        (log_file, (Option<String>), None)
        (max_block_size_in_bytes, (usize), MAX_BLOCK_SIZE_IN_BYTES)
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
        // Snapshot Epoch Count is a consensus parameter. This flag overrides
        // the parameter, which only take effect in `dev` mode.
        (dev_snapshot_epoch_count, (u32), SNAPSHOT_EPOCHS_CAPACITY)
        (era_epoch_count, (u64), ERA_DEFAULT_EPOCH_COUNT)
        (heavy_block_difficulty_ratio, (u64), HEAVY_BLOCK_DEFAULT_DIFFICULTY_RATIO)
        (genesis_accounts, (Option<String>), None)
        (genesis_secrets, (Option<String>), None)
        (initial_difficulty, (Option<u64>), None)
        (network_id, (u64), 1)
        (referee_bound, (usize), REFEREE_DEFAULT_BOUND)
        (timer_chain_beta, (u64), TIMER_CHAIN_DEFAULT_BETA)
        (timer_chain_block_difficulty_ratio, (u64), TIMER_CHAIN_BLOCK_DEFAULT_DIFFICULTY_RATIO)
        (transaction_epoch_bound, (u64), TRANSACTION_DEFAULT_EPOCH_BOUND)

        // Mining section.
        (mining_author, (Option<String>), None)
        (start_mining, (bool), false)
        (stratum_port, (u16), 32525)
        (stratum_secret, (Option<String>), None)
        (use_stratum, (bool), false)

        // Network section.
        (jsonrpc_local_tcp_port, (Option<u16>), None)
        (jsonrpc_local_http_port, (Option<u16>), None)
        (jsonrpc_tcp_port, (Option<u16>), None)
        (jsonrpc_http_port, (Option<u16>), None)
        (jsonrpc_cors, (Option<String>), None)
        (jsonrpc_http_keep_alive, (bool), false)
        (port, (Option<u16>), Some(32323))
        (public_address, (Option<String>), None)
        (udp_port, (Option<u16>), Some(32323))

        // Network parameters section.
        (blocks_request_timeout_ms, (u64), 20_000)
        (check_request_period_ms, (u64), 1_000)
        (chunk_size_byte, (u64), DEFAULT_CHUNK_SIZE)
        (demote_peer_for_timeout, (bool), false)
        (egress_queue_capacity, (usize), 256)
        (egress_min_throttle, (usize), 10)
        (egress_max_throttle, (usize), 64)
        (expire_block_gc_period_s, (u64), 900)
        (headers_request_timeout_ms, (u64), 10_000)
        (heartbeat_period_interval_ms, (u64), 30_000)
        (heartbeat_timeout_ms, (u64), 180_000)
        (inflight_pending_tx_index_maintain_timeout_ms, (u64), 30_000)
        (max_allowed_timeout_in_observing_period, (u64), 10)
        (max_download_state_peers, (usize), 8)
        (max_handshakes, (usize), 64)
        (max_incoming_peers, (usize), 64)
        (max_inflight_request_count, (u64), 64)
        (max_outgoing_peers, (usize), 16)
        (max_outgoing_peers_archive, (usize), 0)
        (max_peers_tx_propagation, (usize), 128)
        (min_peers_tx_propagation, (usize), 8)
        (received_tx_index_maintain_timeout_ms, (u64), 300_000)
        (request_block_with_public, (bool), false)
        (send_tx_period_ms, (u64), 1300)
        (snapshot_candidate_request_timeout_ms, (u64), 10_000)
        (snapshot_chunk_request_timeout_ms, (u64), 30_000)
        (snapshot_manifest_request_timeout_ms, (u64), 30_000)
        (throttling_conf, (Option<String>), None)
        (timeout_observing_period_s, (u64), 600)
        (transaction_request_timeout_ms, (u64), 30_000)
        (tx_maintained_for_peer_timeout_ms, (u64), 600_000)

        // Peer management section.
        (bootnodes, (Option<String>), None)
        (discovery_fast_refresh_timeout_ms, (u64), 10_000)
        (discovery_housekeeping_timeout_ms, (u64), 1_000)
        (discovery_round_timeout_ms, (u64), 500)
        (enable_discovery, (bool), true)
        (netconf_dir, (Option<String>), Some("./net_config".to_string()))
        (net_key, (Option<String>), None)
        (node_table_timeout_s, (u64), 300)
        (node_table_promotion_timeout_s, (u64), 3 * 24 * 3600)
        (session_ip_limits, (String), "1,8,4,2".into())
        (subnet_quota, (usize), 32)

        // Transaction cache/transaction pool section.
        (tx_cache_index_maintain_timeout_ms, (u64), 300_000)
        (tx_pool_size, (usize), 500_000)
        (tx_pool_min_tx_gas_price, (u64), 1)
        (tx_weight_scaling, (u64), 1)
        (tx_weight_exp, (u8), 1)

        // Storage Section.
        (block_cache_gc_period_ms, (u64), 5_000)
        (block_db_type, (String), "rocksdb".to_string())
        // The conflux data dir, if unspecified, is the workdir where conflux is started.
        (conflux_data_dir, (String), "./".to_string())
        // FIXME: use a fixed sub-dir of conflux_data_dir instead.
        (block_db_dir, (String), "./blockchain_db".to_string())
        (ledger_cache_size, (usize), DEFAULT_LEDGER_CACHE_SIZE)
        (rocksdb_cache_size, (Option<usize>), Some(128))
        (rocksdb_compaction_profile, (Option<String>), None)
        (storage_delta_mpts_cache_recent_lfu_factor, (f64), storage::defaults::DEFAULT_DELTA_MPTS_CACHE_RECENT_LFU_FACTOR)
        (storage_delta_mpts_cache_size, (u32), storage::defaults::DEFAULT_DELTA_MPTS_CACHE_SIZE)
        (storage_delta_mpts_cache_start_size, (u32), storage::defaults::DEFAULT_DELTA_MPTS_CACHE_START_SIZE)
        (storage_delta_mpts_node_map_vec_size, (u32), storage::defaults::MAX_CACHED_TRIE_NODES_R_LFU_COUNTER)
        (storage_delta_mpts_slab_idle_size, (u32), storage::defaults::DEFAULT_DELTA_MPTS_SLAB_IDLE_SIZE)
        (storage_max_open_snapshots, (u16), storage::defaults::DEFAULT_MAX_OPEN_SNAPSHOTS)

        // General/Unclassified section.
        (enable_optimistic_execution, (bool), true)
        (future_block_buffer_capacity, (usize), 32768)
        (get_logs_filter_max_limit, (Option<usize>), None)
        (max_trans_count_received_in_catch_up, (u64), 60_000)
        (record_tx_index, (bool), true)

        // TreeGraph Section.
        (candidate_pivot_waiting_timeout_ms, (u64), 10_000)
        (is_consortium, (bool), false)
        (tg_config_path, (Option<String>), Some("./tg_config/tg_config.toml".to_string()))
    }
    {
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
    }
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
        Ok(config)
    }

    pub fn net_config(&self) -> Result<NetworkConfiguration, String> {
        let mut network_config = match self.raw_conf.port {
            Some(port) => NetworkConfiguration::new_with_port(port),
            None => NetworkConfiguration::default(),
        };

        network_config.is_consortium = self.raw_conf.is_consortium;
        network_config.id = self.raw_conf.network_id;
        network_config.discovery_enabled = self.raw_conf.enable_discovery;
        network_config.boot_nodes = to_bootnodes(&self.raw_conf.bootnodes)
            .map_err(|e| format!("failed to parse bootnodes: {}", e))?;
        if self.raw_conf.netconf_dir.is_some() {
            network_config.config_path = self.raw_conf.netconf_dir.clone();
        }
        network_config.use_secret =
            self.raw_conf.net_key.clone().map(|sec_str| {
                sec_str
                    .parse()
                    .expect("net_key is not a valid secret string")
            });
        if let Some(addr) = self.raw_conf.public_address.clone() {
            network_config.public_address = match addr
                .to_socket_addrs()
                .map(|mut i| i.next())
            {
                Ok(sock_addr) => sock_addr,
                Err(_e) => {
                    warn!(target: "network", "public_address in config is invalid");
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
            self.raw_conf.max_outgoing_peers_archive;
        Ok(network_config)
    }

    pub fn cache_config(&self) -> CacheConfig {
        let mut cache_config = CacheConfig::default();
        cache_config.ledger = self.raw_conf.ledger_cache_size;
        cache_config
    }

    pub fn db_config(&self) -> DatabaseConfig {
        let db_dir = &self.raw_conf.block_db_dir;
        if let Err(e) = fs::create_dir_all(&db_dir) {
            panic!("Error creating database directory: {:?}", e);
        }

        let compact_profile =
            match self.raw_conf.rocksdb_compaction_profile.as_ref() {
                Some(p) => db::DatabaseCompactionProfile::from_str(p).unwrap(),
                None => db::DatabaseCompactionProfile::default(),
            };
        db::db_config(
            Path::new(db_dir),
            self.raw_conf.rocksdb_cache_size.clone(),
            compact_profile,
            NUM_COLUMNS.clone(),
            self.raw_conf.rocksdb_disable_wal,
        )
    }

    pub fn consensus_config(&self) -> ConsensusConfig {
        let enable_optimistic_execution = if DEFERRED_STATE_EPOCH_COUNT <= 1 {
            false
        } else {
            self.raw_conf.enable_optimistic_execution
        };
        ConsensusConfig {
            debug_dump_dir_invalid_state_root: self
                .raw_conf
                .debug_dump_dir_invalid_state_root
                .clone(),
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
            },
            bench_mode: false,
            transaction_epoch_bound: self.raw_conf.transaction_epoch_bound,
            referee_bound: self.raw_conf.referee_bound,
        }
    }

    pub fn pow_config(&self) -> ProofOfWorkConfig {
        let stratum_listen_addr =
            if let Some(listen_addr) = self.raw_conf.public_address.clone() {
                listen_addr
            } else {
                String::from("")
            };

        let stratum_secret =
            self.raw_conf
                .stratum_secret
                .clone()
                .map(|hex_str| H256::from_str(hex_str.as_str())
                    .expect("Stratum secret should be 64-digit hex string without 0x prefix"));

        ProofOfWorkConfig::new(
            self.is_test_or_dev_mode(),
            self.raw_conf.use_stratum,
            self.raw_conf.initial_difficulty,
            stratum_listen_addr,
            self.raw_conf.stratum_port,
            stratum_secret,
        )
    }

    pub fn verification_config(&self) -> VerificationConfig {
        VerificationConfig::new(
            self.is_test_mode(),
            self.raw_conf.referee_bound,
            self.raw_conf.max_block_size_in_bytes,
        )
    }

    pub fn tx_gen_config(&self) -> Option<TransactionGeneratorConfig> {
        if self.is_test_mode() &&
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

    pub fn storage_config(&self) -> StorageConfiguration {
        StorageConfiguration {
            consensus_param: ConsensusParam {
                snapshot_epoch_count: if self.is_test_mode() {
                    self.raw_conf.dev_snapshot_epoch_count
                } else {
                    SNAPSHOT_EPOCHS_CAPACITY
                },
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
            max_open_snapshots: self.raw_conf.storage_max_open_snapshots,
            path_delta_mpts_dir: self.raw_conf.conflux_data_dir.clone()
                + StorageConfiguration::DELTA_MPTS_DIR,
            path_snapshot_dir: self.raw_conf.conflux_data_dir.clone()
                + StorageConfiguration::SNAPSHOT_DIR,
            path_snapshot_info_db: self.raw_conf.conflux_data_dir.clone()
                + StorageConfiguration::SNAPSHOT_INFO_DB_PATH,
            path_storage_dir: self.raw_conf.conflux_data_dir.clone()
                + StorageConfiguration::STORAGE_DIR,
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
            future_block_buffer_capacity: self
                .raw_conf
                .future_block_buffer_capacity,
            max_download_state_peers: self.raw_conf.max_download_state_peers,
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
        }
    }

    pub fn state_sync_config(&self) -> StateSyncConfiguration {
        StateSyncConfiguration {
            max_download_peers: self.raw_conf.max_download_state_peers,
            candidate_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_candidate_request_timeout_ms,
            ),
            chunk_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_chunk_request_timeout_ms,
            ),
            manifest_request_timeout: Duration::from_millis(
                self.raw_conf.snapshot_manifest_request_timeout_ms,
            ),
        }
    }

    pub fn data_mananger_config(&self) -> DataManagerConfiguration {
        DataManagerConfiguration::new(
            self.raw_conf.record_tx_index,
            Duration::from_millis(
                self.raw_conf.tx_cache_index_maintain_timeout_ms,
            ),
            match self.raw_conf.block_db_type.as_str() {
                "rocksdb" => DbType::Rocksdb,
                "sqlite" => DbType::Sqlite,
                _ => panic!("Invalid block_db_type parameter!"),
            },
        )
    }

    pub fn sync_graph_config(&self) -> SyncGraphConfig {
        SyncGraphConfig {
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
        let mut config = TxPoolConfig::default();

        config.capacity = self.raw_conf.tx_pool_size;
        config.min_tx_price = self.raw_conf.tx_pool_min_tx_gas_price;
        config.tx_weight_scaling = self.raw_conf.tx_weight_scaling;
        config.tx_weight_exp = self.raw_conf.tx_weight_exp;
        config.transaction_epoch_bound = self.raw_conf.transaction_epoch_bound;

        config
    }

    pub fn rpc_impl_config(&self) -> RpcImplConfiguration {
        RpcImplConfiguration {
            get_logs_filter_max_limit: self.raw_conf.get_logs_filter_max_limit,
        }
    }

    pub fn execution_config(&self) -> ConsensusExecutionConfiguration {
        ConsensusExecutionConfiguration {
            anticone_penalty_ratio: self.raw_conf.anticone_penalty_ratio,
            base_reward_table_in_ucfx: build_base_reward_table(),
            transaction_epoch_bound: self.raw_conf.transaction_epoch_bound,
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
}

/// Validates and formats bootnodes option.
pub fn to_bootnodes(bootnodes: &Option<String>) -> Result<Vec<String>, String> {
    match *bootnodes {
        Some(ref x) if !x.is_empty() => x
            .split(',')
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

pub fn build_base_reward_table() -> Vec<u64> {
    let mut base_reward_table = Vec::new();
    base_reward_table.resize(MINING_REWARD_DECAY_PERIOD_IN_QUARTER, 0);
    for i in 0..MINING_REWARD_DECAY_PERIOD_IN_QUARTER {
        let reward = if i == 0 {
            INITIAL_BASE_MINING_REWARD_IN_UCFX
        } else {
            (base_reward_table[i - 1] as f64
                * MINING_REWARD_DECAY_RATIO_PER_QUARTER)
                .round() as u64
        };
        base_reward_table[i] = reward;
    }
    base_reward_table
}
