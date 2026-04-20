// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;

mod consensus_config;
pub use consensus_config::*;
mod error;
pub use error::*;
mod logger_config;
pub use logger_config::*;
mod metrics_config;
pub use metrics_config::*;
mod mempool_config;
pub use mempool_config::*;
mod secure_backend_config;
pub use secure_backend_config::*;
mod storage_config;
pub use storage_config::*;
mod safety_rules_config;
pub use safety_rules_config::*;
mod test_config;
pub use test_config::*;

/// Config pulls in configuration information from the config file.
/// This is used to set up the nodes and configure various parameters.
/// The config file is broken up into sections for each module
/// so that only that module can be passed around
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(default)]
    pub base: BaseConfig,
    #[serde(default)]
    pub consensus: ConsensusConfig,
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub mempool: MempoolConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub test: Option<TestConfig>,
    #[serde(default)]
    pub failpoints: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaseConfig {
    data_dir: PathBuf,
    pub role: RoleType,
}

impl Default for BaseConfig {
    fn default() -> BaseConfig {
        BaseConfig {
            data_dir: PathBuf::from("./pos_db"),
            role: RoleType::Validator,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleType {
    Validator,
    FullNode,
}

impl RoleType {
    pub fn is_validator(self) -> bool { self == RoleType::Validator }

    pub fn as_str(self) -> &'static str {
        match self {
            RoleType::Validator => "validator",
            RoleType::FullNode => "full_node",
        }
    }
}

impl FromStr for RoleType {
    type Err = ParseRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "validator" => Ok(RoleType::Validator),
            "full_node" => Ok(RoleType::FullNode),
            _ => Err(ParseRoleError(s.to_string())),
        }
    }
}

impl fmt::Debug for RoleType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
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
    pub fn data_dir(&self) -> &Path { &self.base.data_dir }

    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.base.data_dir = data_dir.clone();
        self.consensus.set_data_dir(data_dir.clone());
        self.metrics.set_data_dir(data_dir.clone());
        self.storage.set_data_dir(data_dir);
    }

    /// Reads the config file and returns the configuration object in addition
    /// to doing some post-processing of the config
    /// Paths used in the config are either absolute or relative to the config
    /// location
    pub fn load<P: AsRef<Path>>(input_path: P) -> Result<Self, Error> {
        let config = Self::load_config(&input_path)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(
        &mut self, output_path: P,
    ) -> Result<(), Error> {
        self.save_config(&output_path)?;
        Ok(())
    }
}

pub trait PersistableConfig: Serialize + DeserializeOwned {
    fn load_config<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut file = File::open(&path).map_err(|e| {
            Error::IO(path.as_ref().to_str().unwrap().to_string(), e)
        })?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            Error::IO(path.as_ref().to_str().unwrap().to_string(), e)
        })?;
        Self::parse(&contents)
    }

    fn save_config<P: AsRef<Path>>(&self, output_file: P) -> Result<(), Error> {
        let contents = yaml_serde::to_string(&self)
            .map_err(|e| {
                Error::Yaml(
                    output_file.as_ref().to_str().unwrap().to_string(),
                    e,
                )
            })?
            .into_bytes();
        let mut file = File::create(output_file.as_ref()).map_err(|e| {
            Error::IO(output_file.as_ref().to_str().unwrap().to_string(), e)
        })?;
        file.write_all(&contents).map_err(|e| {
            Error::IO(output_file.as_ref().to_str().unwrap().to_string(), e)
        })?;
        Ok(())
    }

    fn parse(serialized: &str) -> Result<Self, Error> {
        yaml_serde::from_str(&serialized)
            .map_err(|e| Error::Yaml("config".to_string(), e))
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
    pub fn full_path(&self, file_path: &Path) -> PathBuf {
        if file_path.is_relative() {
            self.root_path.join(file_path)
        } else {
            file_path.to_path_buf()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_role_type_conversion() {
        // Verify relationship between RoleType and as_string() is reflexive
        let validator = RoleType::Validator;
        let full_node = RoleType::FullNode;
        let converted_validator =
            RoleType::from_str(validator.as_str()).unwrap();
        let converted_full_node =
            RoleType::from_str(full_node.as_str()).unwrap();
        assert_eq!(converted_validator, validator);
        assert_eq!(converted_full_node, full_node);
    }

    #[test]
    // TODO(joshlind): once the 'matches' crate becomes stable, clean this test
    // up!
    fn verify_parse_role_error_on_invalid_role() {
        let invalid_role_type = "this is not a valid role type";
        match RoleType::from_str(invalid_role_type) {
            Err(ParseRoleError(_)) => { /* the expected error was thrown! */ }
            _ => panic!("A ParseRoleError should have been thrown on the invalid role type!"),
        }
    }
}
