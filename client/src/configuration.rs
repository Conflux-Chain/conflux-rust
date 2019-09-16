// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use cfxcore::{
    block_data_manager::{DataManagerConfiguration, DbType},
    consensus::{ConsensusConfig, ConsensusInnerConfig},
    consensus_parameters::*,
    storage::{self, state_manager::StorageConfiguration},
    sync::ProtocolConfiguration,
};
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
        (port, (Option<u16>), Some(32323))
        (udp_port, (Option<u16>), Some(32323))
        (jsonrpc_local_tcp_port, (Option<u16>), None)
        (jsonrpc_local_http_port, (Option<u16>), None)
        (jsonrpc_tcp_port, (Option<u16>), None)
        (jsonrpc_http_port, (Option<u16>), None)
        (jsonrpc_cors, (Option<String>), None)
        (jsonrpc_http_keep_alive, (bool), false)
        (genesis_accounts, (Option<String>), None)
        (log_conf, (Option<String>), None)
        (log_file, (Option<String>), None)
        (network_id, (u64), 1)
        (bootnodes, (Option<String>), None)
        (netconf_dir, (Option<String>), Some("./net_config".to_string()))
        (net_key, (Option<String>), None)
        (public_address, (Option<String>), None)
        (ledger_cache_size, (Option<usize>), Some(2048))
        (enable_discovery, (bool), true)
        (discovery_fast_refresh_timeout_ms, (u64), 10000)
        (discovery_round_timeout_ms, (u64), 500)
        (discovery_housekeeping_timeout_ms, (u64), 1000)
        (node_table_timeout, (Option<u64>), Some(300))
        (node_table_promotion_timeout, (Option<u64>), Some(3 * 24 * 3600))
        (test_mode, (bool), false)
        (db_cache_size, (Option<usize>), Some(128))
        (db_compaction_profile, (Option<String>), None)
        (db_dir, (Option<String>), Some("./blockchain_db".to_string()))
        (generate_tx, (bool), false)
        (generate_tx_period_us, (Option<u64>), Some(100_000))
        (storage_db_path, (String), "./storage_db".to_string())
        (storage_cache_start_size, (u32), storage::defaults::DEFAULT_CACHE_START_SIZE)
        (storage_cache_size, (u32), storage::defaults::DEFAULT_CACHE_SIZE)
        (storage_recent_lfu_factor, (f64), storage::defaults::DEFAULT_RECENT_LFU_FACTOR)
        (storage_idle_size, (u32), storage::defaults::DEFAULT_IDLE_SIZE)
        (storage_node_map_size, (u32), storage::defaults::MAX_CACHED_TRIE_NODES_R_LFU_COUNTER)
        (send_tx_period_ms, (u64), 1300)
        (check_request_period_ms, (u64), 1000)
        (block_cache_gc_period_ms, (u64), 5000)
        (headers_request_timeout_ms, (u64), 10_000)
        (blocks_request_timeout_ms, (u64), 30_000)
        (transaction_request_timeout_ms, (u64), 30_000)
        (tx_maintained_for_peer_timeout_ms, (u64), 600_000)
        (max_inflight_request_count, (u64), 64)
        (received_tx_index_maintain_timeout_ms, (u64), 600_000)
        (max_trans_count_received_in_catch_up, (u64), 60_000)
        (request_block_with_public, (bool), false)
        (start_mining, (bool), false)
        (initial_difficulty, (Option<u64>), None)
        (tx_pool_size, (usize), 500_000)
        (mining_author, (Option<String>), None)
        (use_stratum, (bool), false)
        (stratum_port, (u16), 32525)
        (stratum_secret, (Option<String>), None)
        (egress_queue_capacity, (usize), 256)
        (egress_min_throttle, (usize), 10)
        (egress_max_throttle, (usize), 64)
        (subnet_quota, (usize), 32)
        (session_ip_limits, (String), "1,8,4,2".into())
        (data_propagate_enabled, (bool), false)
        (data_propagate_interval_ms, (u64), 1000)
        (data_propagate_size, (usize), 1000)
        (record_tx_address, (bool), true)
        // TODO Set default to true when we have new tx pool implementation
        (enable_optimistic_execution, (bool), true)
        (adaptive_weight_alpha_num, (u64), ADAPTIVE_WEIGHT_DEFAULT_ALPHA_NUM)
        (adaptive_weight_alpha_den, (u64), ADAPTIVE_WEIGHT_DEFAULT_ALPHA_DEN)
        (adaptive_weight_beta, (u64), ADAPTIVE_WEIGHT_DEFAULT_BETA)
        (heavy_block_difficulty_ratio, (u64), HEAVY_BLOCK_DEFAULT_DIFFICULTY_RATIO)
        (era_epoch_count, (u64), ERA_DEFAULT_EPOCH_COUNT)
        (era_checkpoint_gap, (u64), ERA_DEFAULT_CHECKPOINT_GAP)
        // FIXME: break into two options: one for enable, one for path.
        (debug_dump_dir_invalid_state_root, (String), "./storage/debug_dump_invalid_state_root/".to_string())
        (metrics_enabled, (bool), false)
        (metrics_report_interval_ms, (u64), 5000)
        (metrics_output_file, (String), "metrics.log".to_string())
        (min_peers_propagation, (usize), 8)
        (max_peers_propagation, (usize), 128)
        (future_block_buffer_capacity, (usize), 32768)
        (txgen_account_count, (usize), 10)
        (tx_cache_count, (usize), 250000)
        (max_download_state_peers, (usize), 8)
        (block_db_type, (String), "rocksdb".to_string())
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
        if let Some(nt_timeout) = self.raw_conf.node_table_timeout {
            network_config.node_table_timeout = Duration::from_secs(nt_timeout);
        }
        if let Some(nt_promotion_timeout) =
            self.raw_conf.node_table_promotion_timeout
        {
            network_config.connection_lifetime_for_promotion =
                Duration::from_secs(nt_promotion_timeout);
        }
        network_config.test_mode = self.raw_conf.test_mode;
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
        Ok(network_config)
    }

    pub fn cache_config(&self) -> CacheConfig {
        let mut cache_config = CacheConfig::default();

        if let Some(db_cache_size) = self.raw_conf.db_cache_size {
            cache_config.db = db_cache_size;
        }
        if let Some(ledger_cache_size) = self.raw_conf.ledger_cache_size {
            cache_config.ledger = ledger_cache_size;
        }
        cache_config
    }

    pub fn db_config(&self) -> DatabaseConfig {
        let db_dir = self.raw_conf.db_dir.as_ref().unwrap();
        if let Err(e) = fs::create_dir_all(&db_dir) {
            panic!("Error creating database directory: {:?}", e);
        }

        let compact_profile = match self.raw_conf.db_compaction_profile.as_ref()
        {
            Some(p) => db::DatabaseCompactionProfile::from_str(p).unwrap(),
            None => db::DatabaseCompactionProfile::default(),
        };
        db::db_config(
            Path::new(db_dir),
            self.raw_conf.db_cache_size.clone(),
            compact_profile,
            NUM_COLUMNS.clone(),
        )
    }

    pub fn consensus_config(&self) -> ConsensusConfig {
        ConsensusConfig {
            debug_dump_dir_invalid_state_root: self
                .raw_conf
                .debug_dump_dir_invalid_state_root
                .clone(),
            inner_conf: ConsensusInnerConfig {
                adaptive_weight_alpha_num: self
                    .raw_conf
                    .adaptive_weight_alpha_num,
                adaptive_weight_alpha_den: self
                    .raw_conf
                    .adaptive_weight_alpha_den,
                adaptive_weight_beta: self.raw_conf.adaptive_weight_beta,
                heavy_block_difficulty_ratio: self
                    .raw_conf
                    .heavy_block_difficulty_ratio,
                era_epoch_count: self.raw_conf.era_epoch_count,
                era_checkpoint_gap: self.raw_conf.era_checkpoint_gap,
                enable_optimistic_execution: self
                    .raw_conf
                    .enable_optimistic_execution,
            },
            bench_mode: false,
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
            self.raw_conf.test_mode,
            self.raw_conf.use_stratum,
            self.raw_conf.initial_difficulty,
            stratum_listen_addr,
            self.raw_conf.stratum_port,
            stratum_secret,
        )
    }

    pub fn verification_config(&self) -> VerificationConfig {
        VerificationConfig::new(self.raw_conf.test_mode)
    }

    pub fn tx_gen_config(&self) -> TransactionGeneratorConfig {
        TransactionGeneratorConfig::new(
            self.raw_conf.generate_tx,
            self.raw_conf.generate_tx_period_us.expect("has default"),
            self.raw_conf.txgen_account_count,
        )
    }

    pub fn storage_config(&self) -> StorageConfiguration {
        StorageConfiguration {
            cache_start_size: self.raw_conf.storage_cache_start_size,
            cache_size: self.raw_conf.storage_cache_size,
            idle_size: self.raw_conf.storage_idle_size,
            node_map_size: self.raw_conf.storage_node_map_size,
            recent_lfu_factor: self.raw_conf.storage_recent_lfu_factor,
        }
    }

    pub fn protocol_config(&self) -> ProtocolConfiguration {
        ProtocolConfiguration {
            send_tx_period: Duration::from_millis(
                self.raw_conf.send_tx_period_ms,
            ),
            check_request_period: Duration::from_millis(
                self.raw_conf.check_request_period_ms,
            ),
            block_cache_gc_period: Duration::from_millis(
                self.raw_conf.block_cache_gc_period_ms,
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
            max_trans_count_received_in_catch_up: self
                .raw_conf
                .max_trans_count_received_in_catch_up,
            min_peers_propagation: self.raw_conf.min_peers_propagation,
            max_peers_propagation: self.raw_conf.max_peers_propagation,
            future_block_buffer_capacity: self
                .raw_conf
                .future_block_buffer_capacity,
            max_download_state_peers: self.raw_conf.max_download_state_peers,
            test_mode: self.raw_conf.test_mode,
        }
    }

    pub fn data_mananger_config(&self) -> DataManagerConfiguration {
        DataManagerConfiguration::new(
            self.raw_conf.record_tx_address,
            self.raw_conf.tx_cache_count,
            match self.raw_conf.block_db_type.as_str() {
                "rocksdb" => DbType::Rocksdb,
                "sqlite" => DbType::Sqlite,
                _ => panic!("Invalid block_db_type parameter!"),
            },
        )
    }
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
