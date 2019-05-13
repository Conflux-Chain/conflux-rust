// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Address, U256};
use keylib::KeyPair;
use secret_store::SecretStore;
use std::{collections::HashMap, fs::File, io::Read};
use toml::Value;

pub fn default(secret_store: &SecretStore) -> HashMap<Address, U256> {
    let balance = U256::from_dec_str("5000000000000000000000000000000000")
        .expect("Not overflow"); // 5*10^33

    let kp = KeyPair::from_secret(
        "46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let kp2 = KeyPair::from_secret(
        "9a6d3ba2b0c7514b16a006ee605055d71b9edfad183aeb2d9790e9d4ccced471"
            .parse()
            .unwrap(),
    )
    .unwrap();

    let mut accounts: HashMap<Address, U256> = HashMap::new();
    accounts.insert(kp.address(), balance);
    accounts.insert(kp2.address(), balance);

    secret_store.insert(kp2);

    accounts
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
                            "balance in toml file requires String type".into()
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
