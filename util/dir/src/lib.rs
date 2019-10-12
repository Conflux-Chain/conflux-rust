// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

#![warn(missing_docs)]

//! Dir utilities for platform-specific operations
extern crate app_dirs;
extern crate ethereum_types;
extern crate home;
extern crate journaldb;

pub mod helpers;
use app_dirs::{get_app_root, AppDataType, AppInfo};
use ethereum_types::{H256, H64};
use helpers::{replace_home, replace_home_and_local};
use journaldb::Algorithm;
use std::{
    fs,
    path::{Path, PathBuf},
};
// re-export platform-specific functions
use platform::*;

pub use home::home_dir;

/// Platform-specific chains path for standard client - Windows only
#[cfg(target_os = "windows")]
pub const CHAINS_PATH: &str = "$LOCAL/chains";
/// Platform-specific chains path for light client - Windows only
#[cfg(target_os = "windows")]
pub const CHAINS_PATH_LIGHT: &str = "$LOCAL/chains_light";
/// Platform-specific chains path for standard client
#[cfg(not(target_os = "windows"))]
pub const CHAINS_PATH: &str = "$BASE/chains";
/// Platform-specific chains path for light client
#[cfg(not(target_os = "windows"))]
pub const CHAINS_PATH_LIGHT: &str = "$BASE/chains_light";

/// Platform-specific cache path - Windows only
#[cfg(target_os = "windows")]
pub const CACHE_PATH: &str = "$LOCAL/cache";
/// Platform-specific cache path
#[cfg(not(target_os = "windows"))]
pub const CACHE_PATH: &str = "$BASE/cache";

// this const is irrelevent cause we do have migrations now,
// but we still use it for backwards compatibility
const LEGACY_CLIENT_DB_VER_STR: &str = "5.3";

#[derive(Debug, PartialEq)]
/// Parity local data directories
pub struct Directories {
    /// Base dir
    pub base: String,
    /// Database dir
    pub db: String,
    /// Cache dir
    pub cache: String,
    /// Dir to store keys
    pub keys: String,
    /// Signer dir
    pub signer: String,
    /// Secrets dir
    pub secretstore: String,
}

impl Default for Directories {
    fn default() -> Self {
        let data_dir = default_data_path();
        let local_dir = default_local_path();
        Directories {
            base: replace_home(&data_dir, "$BASE"),
            db: replace_home_and_local(&data_dir, &local_dir, CHAINS_PATH),
            cache: replace_home_and_local(&data_dir, &local_dir, CACHE_PATH),
            keys: replace_home(&data_dir, "$BASE/keys"),
            signer: replace_home(&data_dir, "$BASE/signer"),
            secretstore: replace_home(&data_dir, "$BASE/secretstore"),
        }
    }
}

impl Directories {
    /// Create local directories
    pub fn create_dirs(
        &self, signer_enabled: bool, secretstore_enabled: bool,
    ) -> Result<(), String> {
        fs::create_dir_all(&self.base).map_err(|e| e.to_string())?;
        fs::create_dir_all(&self.db).map_err(|e| e.to_string())?;
        fs::create_dir_all(&self.cache).map_err(|e| e.to_string())?;
        fs::create_dir_all(&self.keys).map_err(|e| e.to_string())?;
        if signer_enabled {
            fs::create_dir_all(&self.signer).map_err(|e| e.to_string())?;
        }
        if secretstore_enabled {
            fs::create_dir_all(&self.secretstore).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Database paths.
    pub fn database(
        &self, genesis_hash: H256, fork_name: Option<String>, spec_name: String,
    ) -> DatabaseDirectories {
        DatabaseDirectories {
            path: self.db.clone(),
            legacy_path: self.base.clone(),
            genesis_hash,
            fork_name,
            spec_name,
        }
    }

    /// Get the ipc sockets path
    pub fn ipc_path(&self) -> PathBuf {
        let mut dir = Path::new(&self.base).to_path_buf();
        dir.push("ipc");
        dir
    }

    /// Legacy keys path
    // TODO: remove in 1.7
    pub fn legacy_keys_path(&self, testnet: bool) -> PathBuf {
        let mut dir = Path::new(&self.base).to_path_buf();
        if testnet {
            dir.push("testnet_keys");
        } else {
            dir.push("keys");
        }
        dir
    }

    /// Get the keys path
    pub fn keys_path(&self, data_dir: &str) -> PathBuf {
        let mut dir = PathBuf::from(&self.keys);
        dir.push(data_dir);
        dir
    }
}

#[derive(Debug, PartialEq)]
/// Database directories for the given fork.
pub struct DatabaseDirectories {
    /// Base path
    pub path: String,
    /// Legacy path
    pub legacy_path: String,
    /// Genesis hash
    pub genesis_hash: H256,
    /// Name of current fork
    pub fork_name: Option<String>,
    /// Name of current spec
    pub spec_name: String,
}

impl DatabaseDirectories {
    /// Base DB directory for the given fork.
    // TODO: remove in 1.7
    pub fn legacy_fork_path(&self) -> PathBuf {
        let gh = H64::from_slice(&self.genesis_hash.as_bytes()[20..28]);
        Path::new(&self.legacy_path).join(format!(
            "{:x}{}",
            gh,
            self.fork_name
                .as_ref()
                .map(|f| format!("-{}", f))
                .unwrap_or_default()
        ))
    }

    /// Spec root directory for the given fork.
    pub fn spec_root_path(&self) -> PathBuf {
        Path::new(&self.path).join(&self.spec_name)
    }

    /// Generic client path
    pub fn client_path(&self, pruning: Algorithm) -> PathBuf {
        self.db_root_path()
            .join(pruning.as_internal_name_str())
            .join("db")
    }

    /// DB root path, named after genesis hash
    pub fn db_root_path(&self) -> PathBuf {
        let gh = H64::from_slice(&self.genesis_hash.as_bytes()[20..28]);
        self.spec_root_path().join("db").join(format!("{:x}", gh))
    }

    /// DB path
    pub fn db_path(&self, pruning: Algorithm) -> PathBuf {
        self.db_root_path().join(pruning.as_internal_name_str())
    }

    /// Get the root path for database
    // TODO: remove in 1.7
    pub fn legacy_version_path(&self, pruning: Algorithm) -> PathBuf {
        self.legacy_fork_path().join(format!(
            "v{}-sec-{}",
            LEGACY_CLIENT_DB_VER_STR,
            pruning.as_internal_name_str()
        ))
    }

    /// Get user defaults path, legacy way
    // TODO: remove in 1.7
    pub fn legacy_user_defaults_path(&self) -> PathBuf {
        self.legacy_fork_path().join("user_defaults")
    }

    /// Get snapshot path, legacy way
    // TODO: remove in 1.7
    pub fn legacy_snapshot_path(&self) -> PathBuf {
        self.legacy_fork_path().join("snapshot")
    }

    /// Get user defaults path, legacy way
    // TODO: remove in 1.7
    pub fn legacy_network_path(&self) -> PathBuf {
        self.legacy_fork_path().join("network")
    }

    /// Get user defauls path
    pub fn user_defaults_path(&self) -> PathBuf {
        self.spec_root_path().join("user_defaults")
    }

    /// Get the path for the snapshot directory given the genesis hash and fork
    /// name.
    pub fn snapshot_path(&self) -> PathBuf {
        self.db_root_path().join("snapshot")
    }

    /// Get the path for the network directory.
    pub fn network_path(&self) -> PathBuf {
        self.spec_root_path().join("network")
    }
}

/// Default data path
pub fn default_data_path() -> String {
    let app_info = AppInfo {
        name: PRODUCT,
        author: AUTHOR,
    };
    get_app_root(AppDataType::UserData, &app_info)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "$HOME/.parity".to_owned())
}

/// Default local path
pub fn default_local_path() -> String {
    let app_info = AppInfo {
        name: PRODUCT,
        author: AUTHOR,
    };
    get_app_root(AppDataType::UserCache, &app_info)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "$HOME/.parity".to_owned())
}

/// Default hypervisor path
pub fn default_hypervisor_path() -> PathBuf {
    let app_info = AppInfo {
        name: PRODUCT_HYPERVISOR,
        author: AUTHOR,
    };
    get_app_root(AppDataType::UserData, &app_info)
        .unwrap_or_else(|_| "$HOME/.parity-hypervisor".into())
}

/// Get home directory.
fn home() -> PathBuf { home_dir().expect("Failed to get home dir") }

/// Geth path
pub fn geth(testnet: bool) -> PathBuf {
    let mut base = geth_base();
    if testnet {
        base.push("testnet");
    }
    base.push("keystore");
    base
}

/// Parity path for specific chain
pub fn parity(chain: &str) -> PathBuf {
    let mut base = parity_base();
    base.push(chain);
    base
}

#[cfg(target_os = "macos")]
mod platform {
    use std::path::PathBuf;
    pub const AUTHOR: &str = "Parity";
    pub const PRODUCT: &str = "io.parity.ethereum";
    pub const PRODUCT_HYPERVISOR: &str = "io.parity.ethereum-updates";

    pub fn parity_base() -> PathBuf {
        let mut home = super::home();
        home.push("Library");
        home.push("Application Support");
        home.push("io.parity.ethereum");
        home.push("keys");
        home
    }

    pub fn geth_base() -> PathBuf {
        let mut home = super::home();
        home.push("Library");
        home.push("Ethereum");
        home
    }
}

#[cfg(windows)]
mod platform {
    use std::path::PathBuf;
    pub const AUTHOR: &str = "Parity";
    pub const PRODUCT: &str = "Ethereum";
    pub const PRODUCT_HYPERVISOR: &str = "EthereumUpdates";

    pub fn parity_base() -> PathBuf {
        let mut home = super::home();
        home.push("AppData");
        home.push("Roaming");
        home.push("Parity");
        home.push("Ethereum");
        home.push("keys");
        home
    }

    pub fn geth_base() -> PathBuf {
        let mut home = super::home();
        home.push("AppData");
        home.push("Roaming");
        home.push("Ethereum");
        home
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod platform {
    use std::path::PathBuf;
    pub const AUTHOR: &str = "parity";
    pub const PRODUCT: &str = "io.parity.ethereum";
    pub const PRODUCT_HYPERVISOR: &str = "io.parity.ethereum-updates";

    pub fn parity_base() -> PathBuf {
        let mut home = super::home();
        home.push(".local");
        home.push("share");
        home.push("io.parity.ethereum");
        home.push("keys");
        home
    }

    pub fn geth_base() -> PathBuf {
        let mut home = super::home();
        home.push(".ethereum");
        home
    }
}

#[cfg(test)]
mod tests {
    use super::Directories;
    use helpers::{replace_home, replace_home_and_local};

    #[test]
    fn test_default_directories() {
        let data_dir = super::default_data_path();
        let local_dir = super::default_local_path();
        let expected = Directories {
            base: replace_home(&data_dir, "$BASE"),
            db: replace_home_and_local(
                &data_dir,
                &local_dir,
                if cfg!(target_os = "windows") {
                    "$LOCAL/chains"
                } else {
                    "$BASE/chains"
                },
            ),
            cache: replace_home_and_local(
                &data_dir,
                &local_dir,
                if cfg!(target_os = "windows") {
                    "$LOCAL/cache"
                } else {
                    "$BASE/cache"
                },
            ),
            keys: replace_home(&data_dir, "$BASE/keys"),
            signer: replace_home(&data_dir, "$BASE/signer"),
            secretstore: replace_home(&data_dir, "$BASE/secretstore"),
        };
        assert_eq!(expected, Directories::default());
    }
}
