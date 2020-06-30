// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    executive::InternalContractMap,
    parameters::consensus::GENESIS_GAS_LIMIT,
    state::OverlayAccount,
    statedb::{Result as DbResult, StateDb},
    storage::{StorageManager, StorageManagerTrait},
    verification::compute_receipts_root,
};
use cfx_types::{address_util::AddressUtil, Address, U256};
use keylib::KeyPair;
use primitives::{
    Account, Block, BlockHeaderBuilder, BlockReceipts, StorageKey,
    StorageLayout,
};
use secret_store::SecretStore;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    sync::Arc,
};
use toml::Value;

pub const DEV_GENESIS_PRI_KEY: &'static str =
    "46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f";
/// Used in Ethereum replay e2e test.
pub const DEV_GENESIS_PRI_KEY_2: &'static str =
    "9a6d3ba2b0c7514b16a006ee605055d71b9edfad183aeb2d9790e9d4ccced471";

lazy_static! {
    pub static ref DEV_GENESIS_KEY_PAIR: KeyPair =
        KeyPair::from_secret(DEV_GENESIS_PRI_KEY.parse().unwrap()).unwrap();
    pub static ref DEV_GENESIS_KEY_PAIR_2: KeyPair =
        KeyPair::from_secret(DEV_GENESIS_PRI_KEY_2.parse().unwrap()).unwrap();
}

pub fn default(_dev_or_test_mode: bool) -> HashMap<Address, U256> {
    let mut accounts: HashMap<Address, U256> = HashMap::new();
    // FIXME: Decide the genesis initialization for mainnet.
    let balance = U256::from_dec_str("5000000000000000000000000000000000")
        .expect("Not overflow"); // 5*10^33
    accounts.insert(DEV_GENESIS_KEY_PAIR.address(), balance);
    accounts.insert(DEV_GENESIS_KEY_PAIR_2.address(), balance);
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

pub fn initialize_internal_contract_accounts(state: &mut StateDb) {
    || -> DbResult<()> {
        {
            for address in InternalContractMap::new().keys() {
                let account = OverlayAccount::new_basic(
                    address,
                    /* balance = */ U256::zero(),
                    /* nonce = */ U256::one(),
                )
                .as_account()?;
                state.set(
                    StorageKey::AccountKey(address.as_bytes()),
                    &account,
                    None,
                )?;
                // initialize storage layout for internal contracts to make sure
                // that _all_ Conflux contracts have a storage
                // root in our state trie
                state.set_storage_layout(
                    address,
                    &StorageLayout::Regular(0),
                    None,
                )?;
            }
            Ok(())
        }
    }()
    .expect(&concat!(file!(), ":", line!(), ":", column!()));
}

/// ` test_net_version` is used to update the genesis author so that after
/// resetting, the chain of the older version will be discarded
pub fn genesis_block(
    storage_manager: &StorageManager, genesis_accounts: HashMap<Address, U256>,
    test_net_version: Address, initial_difficulty: U256,
) -> Block
{
    let mut state = StateDb::new(storage_manager.get_state_for_genesis_write());
    let mut genesis_block_author = test_net_version;
    genesis_block_author.set_user_account_type_bits();

    let mut total_balance = U256::from(0);
    for (addr, balance) in genesis_accounts {
        let account = Account::new_empty_with_balance(
            &addr,
            &balance,
            &0.into(), /* nonce */
        )
        .unwrap();
        state
            .set(StorageKey::new_account_key(&addr), &account, None)
            .unwrap();
        total_balance += balance;
    }
    state
        .set_total_issued_tokens(&total_balance, None)
        .expect("Cannot set issued tokens in the database!");
    initialize_internal_contract_accounts(&mut state);

    let state_root = state.compute_state_root().unwrap();
    let receipt_root = compute_receipts_root(&vec![Arc::new(BlockReceipts {
        receipts: vec![],
        secondary_reward: U256::zero(),
    })]);
    let mut genesis = Block::new(
        BlockHeaderBuilder::new()
            .with_deferred_state_root(state_root.aux_info.state_root_hash)
            .with_deferred_receipts_root(receipt_root)
            .with_gas_limit(GENESIS_GAS_LIMIT.into())
            .with_author(genesis_block_author)
            .with_difficulty(initial_difficulty)
            .build(),
        Vec::new(),
    );
    genesis.block_header.compute_hash();
    debug!(
        "Initialize genesis_block={:?} hash={:?}",
        genesis,
        genesis.hash()
    );
    state.commit(genesis.block_header.hash()).unwrap();
    genesis
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
