// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use blockgen::BlockGeneratorConfig;
use cfxcore::{
    storage::{self, state_manager::StorageConfiguration},
    sync::ProtocolConfiguration,
};
use txgen::TransactionGeneratorConfig;
/// usage:
/// ```
/// build_config! {
///     {
///         (name, (type), default_value)
///         ...
///     }
///     {
///         (name, (type), default_value, converter)
///     }
/// }
/// ```
/// `converter` is a function used to convert a provided String to `Result<type,
/// String>`. For each entry, field `name` of type `type` will be created in
/// `RawConfiguration`, and it will be assigned to the value passed through
/// commandline argument or configuration file. Commandline argument will
/// override the configuration file if the parameter is given in both.
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
        (log_conf, (Option<String>), None)
        (log_file, (Option<String>), None)
        (bootnodes, (Option<String>), None)
        (netconf_dir, (Option<String>), Some("./net_config".to_string()))
        (net_key, (Option<String>), None)
        (public_address, (Option<String>), None)
        (ledger_cache_size, (Option<usize>), Some(2048))
        (enable_discovery, (bool), true)
        (node_table_timeout, (Option<u64>), Some(300))
        (node_table_promotion_timeout, (Option<u64>), Some(3 * 24 * 3600))
        (fast_recover, (bool), true)
        (test_mode, (bool), false)
        (db_cache_size, (Option<usize>), Some(128))
        (db_compaction_profile, (Option<String>), None)
        (db_dir, (Option<String>), Some("./blockchain_db".to_string()))
        (generate_tx, (bool), false)
        (generate_tx_period_ms, (Option<u64>), Some(100))
        (storage_cache_start_size, (u32), storage::defaults::DEFAULT_CACHE_START_SIZE)
        (storage_cache_size, (u32), storage::defaults::DEFAULT_CACHE_SIZE)
        (storage_recent_lfu_factor, (f64), storage::defaults::DEFAULT_RECENT_LFU_FACTOR)
        (storage_idle_size, (u32), storage::defaults::DEFAULT_IDLE_SIZE)
        (storage_node_map_size, (u32), storage::defaults::MAX_CACHED_TRIE_NODES_R_LFU_COUNTER)
        (send_tx_period_ms, (u64), 1300)
        (check_request_period_ms, (u64), 5000)
        (block_cache_gc_period_ms, (u64), 5000)
        (persist_terminal_period_ms, (u64), 60_000)
        (headers_request_timeout_ms, (u64), 30_000)
        (blocks_request_timeout_ms, (u64), 120_000)
        (load_test_chain, (Option<String>), None)
        (start_mining, (bool), false)
        (initial_difficulty, (Option<u64>), None)
        (tx_pool_size, (usize), 500_000)
        (mining_author, (Option<String>), None)
        (egress_queue_capacity, (usize), 256)
        (egress_min_throttle, (usize), 10)
        (egress_max_throttle, (usize), 64)
        (p2p_nodes_per_ip, (usize), 1)
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

    pub fn net_config(&self) -> NetworkConfiguration {
        let mut network_config = match self.raw_conf.port {
            Some(port) => NetworkConfiguration::new_with_port(port),
            None => NetworkConfiguration::default(),
        };

        network_config.discovery_enabled = self.raw_conf.enable_discovery;
        network_config.boot_nodes = to_bootnodes(&self.raw_conf.bootnodes)
            .expect("Error parsing bootnodes!");
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
        network_config.nodes_per_ip = self.raw_conf.p2p_nodes_per_ip;
        network_config
    }

    pub fn fast_recover(&self) -> bool { self.raw_conf.fast_recover }

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

    pub fn pow_config(&self) -> ProofOfWorkConfig {
        ProofOfWorkConfig::new(
            self.raw_conf.test_mode,
            self.raw_conf.initial_difficulty,
        )
    }

    pub fn verification_config(&self) -> VerificationConfig {
        VerificationConfig::new(self.raw_conf.test_mode)
    }

    pub fn tx_gen_config(&self) -> TransactionGeneratorConfig {
        TransactionGeneratorConfig::new(
            self.raw_conf.generate_tx,
            self.raw_conf.generate_tx_period_ms.expect("has default"),
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
            persist_terminal_period: Duration::from_millis(
                self.raw_conf.persist_terminal_period_ms,
            ),
            headers_request_timeout: Duration::from_millis(
                self.raw_conf.headers_request_timeout_ms,
            ),
            blocks_request_timeout: Duration::from_millis(
                self.raw_conf.blocks_request_timeout_ms,
            ),
        }
    }

    pub fn blockgen_config(&self) -> BlockGeneratorConfig {
        BlockGeneratorConfig {
            test_chain_path: self.raw_conf.load_test_chain.clone(),
        }
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
