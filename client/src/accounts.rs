// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use app_dirs::{get_app_root, AppDataType, AppInfo};
use dir::helpers::replace_home;
use ethcore_accounts::{AccountProvider, AccountProviderSettings};
use ethstore::{accounts_dir::RootDiskDirectory, EthStore};
use std::path::PathBuf;

pub fn account_provider(
    dir: Option<String>, sstore_iterations: Option<u32>,
) -> Result<AccountProvider, String> {
    let dir = match dir {
        Some(dir) => dir,
        None => keys_path(),
    };
    let dir = Box::new(keys_dir(dir)?);
    let secret_store = Box::new(secret_store(dir, sstore_iterations)?);
    Ok(AccountProvider::new(
        secret_store,
        AccountProviderSettings::default(),
    ))
}

pub fn keys_dir(path: String) -> Result<RootDiskDirectory, String> {
    let mut path = PathBuf::from(&path);
    // TODO: make a global constant
    path.push("conflux".to_string());
    RootDiskDirectory::create(path)
        .map_err(|e| format!("Could not open keys directory: {}", e))
}

fn secret_store(
    dir: Box<RootDiskDirectory>, iterations: Option<u32>,
) -> Result<EthStore, String> {
    match iterations {
        Some(i) => EthStore::open_with_iterations(dir, i),
        None => EthStore::open(dir),
    }
    .map_err(|e| format!("Could not open keys store: {}", e))
}

/// Default data path
fn default_data_path() -> String {
    let app_info = AppInfo {
        name: "Conflux",
        author: "conflux",
    };
    get_app_root(AppDataType::UserData, &app_info)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "$HOME/.conflux".to_owned())
}

pub fn keys_path() -> String {
    let data_path = default_data_path();
    replace_home(&data_path, "$BASE/keys")
}
