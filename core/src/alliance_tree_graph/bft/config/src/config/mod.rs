// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{ensure, Result};
use keccak_hash::keccak;
use rand::{rngs::StdRng, SeedableRng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use toml;

use log::*;

mod admission_control_config;
pub use admission_control_config::*;
mod consensus_config;
pub use consensus_config::*;
mod debug_interface_config;
pub use debug_interface_config::*;
mod execution_config;
pub use execution_config::*;
mod logger_config;
pub use logger_config::*;
mod metrics_config;
pub use metrics_config::*;
mod mempool_config;
pub use mempool_config::*;
mod network_config;
pub use network_config::*;
mod state_sync_config;
pub use state_sync_config::*;
mod storage_config;
pub use storage_config::*;
mod safety_rules_config;
pub use safety_rules_config::*;
mod test_config;
pub use test_config::*;
mod vm_config;
use crate::waypoint::Waypoint;
use libra_types::account_address::AccountAddress;
pub use vm_config::*;

/// Config pulls in configuration information from the config file.
/// This is used to set up the nodes and configure various parameters.
/// The config file is broken up into sections for each module
/// so that only that module can be passed around
#[cfg_attr(any(test, feature = "fuzzing"), derive(Clone))]
#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(default)]
    pub admission_control: AdmissionControlConfig,
    #[serde(default)]
    pub base: BaseConfig,
    #[serde(default)]
    pub consensus: ConsensusConfig,
    #[serde(default)]
    pub debug_interface: DebugInterfaceConfig,
    #[serde(default)]
    pub execution: ExecutionConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub full_node_networks: Vec<NetworkConfig>,
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub mempool: MempoolConfig,
    #[serde(default)]
    pub state_sync: StateSyncConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub test: Option<TestConfig>,
    #[serde(default)]
    pub validator_network: Option<NetworkConfig>,
    #[serde(default)]
    pub enable_state_expose: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaseConfig {
    data_dir: PathBuf,
    pub role: RoleType,
    pub waypoint: Option<Waypoint>,
}

impl Default for BaseConfig {
    fn default() -> BaseConfig {
        BaseConfig {
            data_dir: PathBuf::from("./opt/libra/data/common"),
            role: RoleType::Validator,
            waypoint: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleType {
    Validator,
    FullNode,
}

impl RoleType {
    pub fn is_validator(&self) -> bool { *self == RoleType::Validator }

    pub fn as_str(&self) -> &'static str {
        match self {
            RoleType::Validator => "validator",
            RoleType::FullNode => "full_node",
        }
    }
}

impl std::str::FromStr for RoleType {
    type Err = ParseRoleError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "validator" => Ok(RoleType::Validator),
            "full_node" => Ok(RoleType::FullNode),
            _ => Err(ParseRoleError(s.to_string())),
        }
    }
}

impl fmt::Display for RoleType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Error)]
#[error("Invalid node role: {0}")]
pub struct ParseRoleError(String);

impl NodeConfig {
    pub fn data_dir(&self) -> &PathBuf { &self.base.data_dir }

    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.base.data_dir = data_dir.clone();
        self.metrics.set_data_dir(data_dir.clone());
        self.storage.set_data_dir(data_dir.clone());
        self.consensus.safety_rules.set_data_dir(data_dir);
    }

    /// This clones the underlying data except for the keypair so that this
    /// config can be used as a template for another config.
    pub fn clone_for_template(&self) -> Self {
        Self {
            admission_control: self.admission_control.clone(),
            base: self.base.clone(),
            consensus: self.consensus.clone_for_template(),
            debug_interface: self.debug_interface.clone(),
            execution: self.execution.clone(),
            full_node_networks: self
                .full_node_networks
                .iter()
                .map(|c| c.clone_for_template())
                .collect(),
            logger: self.logger.clone(),
            metrics: self.metrics.clone(),
            mempool: self.mempool.clone(),
            state_sync: self.state_sync.clone(),
            storage: self.storage.clone(),
            test: None,
            validator_network: if let Some(n) = &self.validator_network {
                Some(n.clone_for_template())
            } else {
                None
            },
            //vm_config: self.vm_config.clone(),
            enable_state_expose: false,
        }
    }

    /// Reads the config file and returns the configuration object in addition
    /// to doing some post-processing of the config
    /// Paths used in the config are either absolute or relative to the config
    /// location
    pub fn load<P: AsRef<Path>>(
        input_path: P, keypair: Option<ConsensusKeyPair>,
    ) -> Result<Self> {
        let mut config = Self::load_config(&input_path)?;
        ensure!(config.base.role.is_validator(), "Node must be validator");
        ensure!(keypair.is_some(), "key pair must be provided");

        /*
        if config.base.role.is_validator() {
            ensure!(
                config.validator_network.is_some(),
                "Missing a validator network config for a validator node"
            );
        } else {
            ensure!(
                config.validator_network.is_none(),
                "Provided a validator network config for a full_node node"
            );
        }
        */

        let public_key = keypair.as_ref().unwrap().public().clone();

        let input_dir = RootPath::new(input_path);
        info!("BFT config root path: {:?}", &input_dir);
        config.consensus.load(&input_dir, keypair)?;
        let validator_set =
            config.consensus.consensus_peers.get_validator_set();
        // Must happen after config.consensus.load()
        config.execution.load(&input_dir, validator_set)?;

        let mut network = NetworkConfig::default();
        let peer_id = AccountAddress::new(keccak(public_key.public()).into());
        network.load(&input_dir, RoleType::Validator, peer_id)?;
        config.validator_network = Some(network);
        /*
        if let Some(network) = &mut config.validator_network {
            network.load(&input_dir, RoleType::Validator)?;
        }
        for network in &mut config.full_node_networks {
            network.load(&input_dir, RoleType::FullNode)?;
        }
        */
        config.set_data_dir(config.data_dir().clone());
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&mut self, output_path: P) -> Result<()> {
        let output_dir = RootPath::new(&output_path);
        self.consensus.save(&output_dir)?;
        self.execution.save(&output_dir)?;
        if let Some(network) = &mut self.validator_network {
            network.save(&output_dir)?;
        }
        for network in &mut self.full_node_networks {
            network.save(&output_dir)?;
        }
        // This must be last as calling save on subconfigs may change their
        // fields
        self.save_config(&output_path)?;
        Ok(())
    }

    /// Returns true if network_config is for an upstream network
    /*
    pub fn is_upstream_network(&self, network_config: &NetworkConfig) -> bool {
        self.state_sync
            .upstream_peers
            .upstream_peers
            .iter()
            .any(|peer_id| {
                network_config.network_peers.peers.contains_key(peer_id)
            })
    }
    */

    pub fn randomize_ports(&mut self) {
        self.admission_control.randomize_ports();
        self.debug_interface.randomize_ports();
        self.execution.randomize_ports();
        self.mempool.randomize_ports();
        self.storage.randomize_ports();
    }

    pub fn random() -> Self {
        let mut rng = StdRng::from_seed([0u8; 32]);
        Self::random_with_rng(&mut rng)
    }

    pub fn random_with_rng(rng: &mut StdRng) -> Self {
        let mut config = NodeConfig::default();
        config.random_internal(rng);
        config
    }

    pub fn random_with_template(template: &Self, rng: &mut StdRng) -> Self {
        let mut config = template.clone_for_template();
        config.random_internal(rng);
        config
    }

    fn random_internal(&mut self, _rng: &mut StdRng) {
        /*
        let mut test = TestConfig::new_with_temp_dir();

        if self.base.role == RoleType::Validator {
            test.random(rng);
            let peer_id = PeerId::from_public_key(
                test.account_keypair.as_ref().unwrap().public(),
            );

            if self.validator_network.is_none() {
                self.validator_network = Some(NetworkConfig::default());
            }

            let validator_network = self.validator_network.as_mut().unwrap();
            validator_network.random_with_peer_id(rng, Some(peer_id));
            self.consensus.random(rng, peer_id);
        } else {
            self.validator_network = None;
            if self.full_node_networks.is_empty() {
                self.full_node_networks.push(NetworkConfig::default());
            }
            for network in &mut self.full_node_networks {
                network.random(rng);
            }
        }
        self.set_data_dir(test.temp_dir().unwrap().to_path_buf());
        self.test = Some(test);
        */
    }
}

pub trait PersistableConfig: Serialize + DeserializeOwned {
    fn load_config<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(&path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Self::parse(&contents)
    }

    fn save_config<P: AsRef<Path>>(&self, output_file: P) -> Result<()> {
        let contents = toml::to_vec(&self)?;
        let mut file = File::create(output_file)?;
        file.write_all(&contents)?;
        Ok(())
    }

    fn parse(serialized: &str) -> Result<Self> {
        Ok(toml::from_str(&serialized)?)
    }
}

impl<T: ?Sized> PersistableConfig for T where T: Serialize + DeserializeOwned {}

#[derive(Debug)]
pub struct RootPath {
    root_path: PathBuf,
}

impl RootPath {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let root_path = if let Some(parent) = path.as_ref().parent() {
            parent.to_path_buf()
        } else {
            PathBuf::from("")
        };

        Self { root_path }
    }

    /// This function assumes that the path is already a directory
    pub fn new_path<P: AsRef<Path>>(path: P) -> Self {
        let root_path = path.as_ref().to_path_buf();
        Self { root_path }
    }

    /// This adds a full path when loading / storing if one is not specified
    pub fn full_path(&self, file_path: &PathBuf) -> PathBuf {
        if file_path.is_relative() {
            self.root_path.join(file_path)
        } else {
            file_path.clone()
        }
    }
}
