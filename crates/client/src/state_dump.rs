use crate::common::initialize_not_light_node_modules;
use cfx_config::Configuration;
use cfx_rpc_eth_types::{AccountState, StateDump, EOA_STORAGE_ROOT_H256};
use cfx_rpc_primitives::Bytes;
use cfx_statedb::{StateDbExt, StateDbGeneric};
use cfx_storage::state_manager::StateManagerTrait;
use cfx_types::{Address, Space, H256, U256};
use cfxcore::NodeType;
use chrono::Utc;
use keccak_hash::{keccak, KECCAK_EMPTY};
use parking_lot::{Condvar, Mutex};
use primitives::{
    Account, SkipInputCheck, StorageKey, StorageKeyWithSpace, StorageValue,
};
use rlp::Rlp;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    ops::Deref,
    path::Path,
    sync::Arc,
    thread,
    time::Duration,
};

pub struct StateDumpConfig {
    pub start_address: Address,
    pub limit: u64,
    pub block: Option<u64>,
    pub no_code: bool,
    pub no_storage: bool,
    pub out_put_path: String,
}

// This method will read all data (k, v) from the Conflux state tree (including
// core space and espace accounts, code, storage, deposit, vote_list) into
// memory at once, then parse and assemble them and assemble all account states
// into a StateDump struct and return it
pub fn dump_whole_state(
    conf: &mut Configuration, exit_cond_var: Arc<(Mutex<bool>, Condvar)>,
    config: &StateDumpConfig,
) -> Result<StateDump, String> {
    let (mut state_db, state_root) =
        prepare_state_db(conf, exit_cond_var, config)?;

    let accounts =
        export_space_accounts(&mut state_db, Space::Ethereum, config)
            .map_err(|e| e.to_string())?;

    let state_dump = StateDump {
        root: state_root,
        accounts,
        next: None,
    };

    Ok(state_dump)
}

// This method will iterate through the entire state tree, storing each found
// account in a temporary map After iterating through all accounts, it will
// retrieve the code and storage for each account, then call the callback method
// Pass the AccountState as a parameter to the callback method, which will
// handle the AccountState
pub fn iterate_dump_whole_state<F: Fn(AccountState)>(
    conf: &mut Configuration, exit_cond_var: Arc<(Mutex<bool>, Condvar)>,
    config: &StateDumpConfig, callback: F,
) -> Result<H256, String> {
    let (mut state_db, state_root) =
        prepare_state_db(conf, exit_cond_var, config)?;

    export_space_accounts_with_callback(
        &mut state_db,
        Space::Ethereum,
        config,
        callback,
    )
    .map_err(|e| e.to_string())?;

    Ok(state_root)
}

fn prepare_state_db(
    conf: &mut Configuration, exit_cond_var: Arc<(Mutex<bool>, Condvar)>,
    config: &StateDumpConfig,
) -> Result<(StateDbGeneric, H256), String> {
    println("Preparing state...");
    let (
        data_man,
        _,
        _,
        consensus,
        sync_service,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = initialize_not_light_node_modules(
        conf,
        exit_cond_var,
        NodeType::Archive,
    )?;

    while sync_service.catch_up_mode() {
        thread::sleep(Duration::from_secs(1));
    }

    /*
    1. Get the state at the target epoch, or the latest state if target_epoch is None
    2. Iterate through the state, and dump the account state
    */

    let state_manager = data_man.storage_manager.clone();
    let target_height = match config.block {
        Some(epoch) => epoch,
        None => consensus.latest_confirmed_epoch_number(),
    };

    let epoch_hash = consensus
        .get_hash_from_epoch_number(target_height.into())
        .map_err(|e| e.to_string())?;

    let block = consensus
        .get_phantom_block_by_hash(&epoch_hash, false)?
        .expect("Failed to get block");

    let state_root = block.pivot_header.deferred_state_root();

    let state_index = data_man
        .get_state_readonly_index(&epoch_hash)
        .ok_or("Failed to get state index")?;

    let state = state_manager
        .get_state_no_commit(state_index, true, Some(Space::Ethereum))
        .map_err(|e| e.to_string())?
        .ok_or("Failed to get state")?;

    let state_db = StateDbGeneric::new(state);

    Ok((state_db, state_root.clone()))
}

fn export_space_accounts(
    state: &mut StateDbGeneric, space: Space, config: &StateDumpConfig,
) -> Result<BTreeMap<Address, AccountState>, Box<dyn std::error::Error>> {
    println("Start to iterate state...");
    let empty_key = StorageKey::EmptyKey.with_space(space);
    let kv_pairs = state.read_all(empty_key, None)?;

    let mut accounts_map = BTreeMap::new();
    let mut codes_map = HashMap::new();
    let mut storage_map = HashMap::new();

    for (key, value) in kv_pairs {
        let storage_key_with_space =
            StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key);
        if storage_key_with_space.space != space {
            continue;
        }
        match storage_key_with_space.key {
            StorageKey::AccountKey(address_bytes) => {
                let address = Address::from_slice(address_bytes);
                println(&format!("Find account: {:?}", address));
                let account =
                    Account::new_from_rlp(address, &Rlp::new(&value))?;
                accounts_map.insert(address, account);
            }
            StorageKey::CodeKey {
                address_bytes,
                code_hash_bytes: _,
            } => {
                if config.no_code {
                    continue;
                }

                let address = Address::from_slice(address_bytes);
                let code = Bytes(value.to_vec());
                codes_map.insert(address, code);
            }
            StorageKey::StorageKey {
                address_bytes,
                storage_key,
            } => {
                if config.no_storage {
                    continue;
                }

                let address = Address::from_slice(address_bytes);
                let h256_storage_key = H256::from_slice(storage_key);
                let storage_value_with_owner: StorageValue =
                    rlp::decode(&value)?;
                let account_storage_map =
                    storage_map.entry(address).or_insert(BTreeMap::new());
                account_storage_map
                    .insert(h256_storage_key, storage_value_with_owner.value);
            }
            _ => {
                continue;
            }
        }
    }

    let mut accounts = BTreeMap::new();

    for (address, account) in accounts_map {
        let is_contract = account.code_hash != KECCAK_EMPTY;
        // conflux state tree don't have storage root, so we use a fixed value
        let root = EOA_STORAGE_ROOT_H256;
        let address_hash = keccak(address);

        let code = if is_contract {
            codes_map.get(&address).cloned()
        } else {
            if let Some(code) = codes_map.get(&address) {
                println(&format!("no-contract account have code: {:?}", code));
            }
            None
        };

        let storage = if is_contract {
            storage_map.get(&address).cloned()
        } else {
            if let Some(_storage) = storage_map.get(&address) {
                println(&format!("no-contract account have storage"));
            }
            None
        };

        let account_state = AccountState {
            balance: account.balance,
            nonce: account.nonce.as_u64(),
            root,
            code_hash: account.code_hash,
            code,
            storage,
            address: Some(address),
            address_hash: Some(address_hash),
        };

        accounts.insert(address, account_state);

        if config.limit > 0 && accounts.len() >= config.limit as usize {
            break;
        }
    }

    Ok(accounts)
}

pub fn export_space_accounts_with_callback<F: Fn(AccountState)>(
    state: &mut StateDbGeneric, space: Space, config: &StateDumpConfig,
    callback: F,
) -> Result<(), Box<dyn std::error::Error>> {
    println("Start to iterate state...");
    let mut found_accounts = 0;
    let mut core_space_key_count: u64 = 0;
    let mut total_key_count: u64 = 0;

    for i in 0..=255 {
        let prefix = [i];
        let start_key = StorageKey::AddressPrefixKey(&prefix).with_space(space);

        let mut account_states = BTreeMap::new();

        let mut inner_callback = |(key, value): (Vec<u8>, Box<[u8]>)| {
            total_key_count += 1;

            if total_key_count % 10000 == 0 {
                println(&format!(
                    "total_key_count: {}, core_space_key_count: {}",
                    total_key_count, core_space_key_count
                ));
            }

            let storage_key_with_space =
                StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key);
            if storage_key_with_space.space != space {
                core_space_key_count += 1;
                return;
            }

            if let StorageKey::AccountKey(address_bytes) =
                storage_key_with_space.key
            {
                let address = Address::from_slice(address_bytes);
                println(&format!("Find account: {:?}", address));
                let account = Account::new_from_rlp(address, &Rlp::new(&value))
                    .expect("Failed to decode account");

                account_states.insert(address, account);
            }
        };

        state.read_all_with_callback(start_key, &mut inner_callback, true)?;

        if account_states.len() > 0 {
            println("Start to read account code and storage data...");
        }

        for (_address, account) in account_states {
            let account_state =
                get_account_state(state, &account, config, space)?;
            callback(account_state);
            found_accounts += 1;
            if config.limit > 0 && found_accounts >= config.limit as usize {
                break;
            }
        }
    }

    Ok(())
}

#[allow(unused)]
fn get_account_state(
    state: &mut StateDbGeneric, account: &Account, config: &StateDumpConfig,
    space: Space,
) -> Result<AccountState, Box<dyn std::error::Error>> {
    let address = account.address();

    let is_contract = account.code_hash != KECCAK_EMPTY;
    // get code
    let code = if is_contract && !config.no_code {
        state
            .get_code(address, &account.code_hash)?
            .map(|code_info| Bytes(code_info.code.deref().to_vec()))
    } else {
        None
    };

    let storage = if is_contract && !config.no_storage {
        let storage =
            get_contract_storage(state, &address.address, space, config)?;
        Some(storage)
    } else {
        None
    };

    // conflux state tree don't have storage root, so we use a fixed value
    let root = EOA_STORAGE_ROOT_H256;

    let address_hash = keccak(address.address);

    Ok(AccountState {
        balance: account.balance,
        nonce: account.nonce.as_u64(),
        root,
        code_hash: account.code_hash,
        code,
        storage,
        address: Some(address.address),
        address_hash: Some(address_hash),
    })
}

fn get_contract_storage(
    state: &mut StateDbGeneric, address: &Address, space: Space,
    config: &StateDumpConfig,
) -> Result<BTreeMap<H256, U256>, Box<dyn std::error::Error>> {
    let mut storage: BTreeMap<H256, U256> = Default::default();
    let mut chunk_count = 0;

    let mut inner_callback = |(key, value): (Vec<u8>, Box<[u8]>)| {
        let storage_key_with_space =
            StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key);
        if storage_key_with_space.space != space {
            return;
        }

        if let StorageKey::StorageKey {
            address_bytes: _,
            storage_key,
        } = storage_key_with_space.key
        {
            let h256_storage_key = H256::from_slice(storage_key);
            let storage_value_with_owner: StorageValue =
                rlp::decode(&value).expect("Failed to decode storage value");
            storage.insert(h256_storage_key, storage_value_with_owner.value);

            if storage.len() == 5000_000 {
                chunk_count += 1;
                let name = format!("{:?}-chunk{}.json", address, chunk_count);
                let file_path = Path::new(&config.out_put_path).join(&name);
                let json_content = serde_json::to_string_pretty(&storage)
                    .expect("Failed to serialize storage");
                fs::write(&file_path, json_content)
                    .expect("Failed to write storage file");
                storage.clear();
            }
        };
    };

    let start_key = StorageKey::new_storage_root_key(address).with_space(space);
    state.read_all_with_callback(start_key, &mut inner_callback, false)?;

    Ok(storage)
}

fn println(message: &str) {
    println!("[{}] {}", Utc::now().format("%Y-%m-%d %H:%M:%S"), message);
}
