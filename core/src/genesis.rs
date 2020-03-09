// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Address, U256};
use keylib::KeyPair;
use secret_store::SecretStore;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
};
use toml::Value;

pub const DEV_GENESIS_PRI_KEY: &'static str =
    "46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f";
/// Used in Ethereum replay e2e test.
pub const DEV_GENESIS_PRI_KEY_2: &'static str =
    "9a6d3ba2b0c7514b16a006ee605055d71b9edfad183aeb2d9790e9d4ccced471";

lazy_static! {
    pub static ref DEV_GENESIS_KEY_PAIR: KeyPair =
        KeyPair::from_secret(DEV_GENESIS_PRI_KEY.parse().unwrap(),).unwrap();
    pub static ref DEV_GENESIS_KEY_PAIR_2: KeyPair =
        KeyPair::from_secret(DEV_GENESIS_PRI_KEY_2.parse().unwrap(),).unwrap();
}

pub fn default(dev_or_test_mode: bool) -> HashMap<Address, U256> {
    let mut accounts: HashMap<Address, U256> = HashMap::new();
    if dev_or_test_mode {
        let balance = U256::from_dec_str("5000000000000000000000000000000000")
            .expect("Not overflow"); // 5*10^33
        accounts.insert(DEV_GENESIS_KEY_PAIR.address(), balance);
        accounts.insert(DEV_GENESIS_KEY_PAIR_2.address(), balance);
    }
    accounts
}

pub fn load_secrets_file(
    path: &String, secret_store: &SecretStore,
) -> Result<HashMap<Address, U256>, String> {
    let file = File::open(path)
        .map_err(|e| format!("failed to open file: {:?}", e))?;
    let buffered = BufReader::new(file);

    let mut accounts: HashMap<Address, U256> = HashMap::new();
    let balance =
        U256::from_dec_str("10000000000000000000000").map_err(|e| {
            format!(
                "failed to parse balance: value = {}, error = {:?}",
                "10000000000000000000000", e
            )
        })?;
    for line in buffered.lines() {
        let keypair =
            KeyPair::from_secret(line.unwrap().parse().unwrap()).unwrap();
        accounts.insert(keypair.address(), balance.clone());
        secret_store.insert(keypair);
    }
    Ok(accounts)
}

pub fn load_file(path: &String) -> Result<HashMap<Address, U256>, String> {
    let mut content = String::new();
    let mut file = File::open(path)
        .map_err(|e| format!("failed to open file: {:?}", e))?;
    file.read_to_string(&mut content)
        .map_err(|e| format!("failed to read file content: {:?}", e))?;
    let account_values = content
        .parse::<toml::Value>()
        .map_err(|e| format!("failed to parse toml file: {:?}", e))?;

    let mut accounts: HashMap<Address, U256> = HashMap::new();
    match account_values {
        Value::Table(table) => {
            for (key, value) in table {
                let addr = key.parse::<Address>().map_err(|e| {
                    format!(
                        "failed to parse address: value = {}, error = {:?}",
                        key, e
                    )
                })?;

                match value {
                    Value::String(balance) => {
                        let balance = U256::from_dec_str(&balance).map_err(|e| format!("failed to parse balance: value = {}, error = {:?}", balance, e))?;
                        accounts.insert(addr, balance);
                    }
                    _ => {
                        return Err(
                            "balance in toml file requires String type".into(),
                        );
                    }
                }
            }
        }
        _ => {
            return Err(format!(
                "invalid root value type {:?} in toml file",
                account_values.type_str()
            ));
        }
    }

    Ok(accounts)
}
