use crate::common::initialize_not_light_node_modules;
use cfx_config::Configuration;
use cfx_rpc_eth_types::{AccountState, StateDump, EOA_STORAGE_ROOT_H256};
use cfx_rpc_primitives::Bytes;
use cfx_statedb::{StateDbExt, StateDbGeneric};
use cfx_storage::{
    state_manager::StateManagerTrait, utils::to_key_prefix_iter_upper_bound,
    KeyValueDbIterableTrait,
};
use cfx_types::{Address, Space, H256};
use cfxcore::NodeType;
use fallible_iterator::FallibleIterator;
use keccak_hash::{keccak, KECCAK_EMPTY};
use parking_lot::{Condvar, Mutex};
use primitives::{
    Account, SkipInputCheck, StorageKey, StorageKeyWithSpace, StorageValue,
};
use rlp::Rlp;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::Deref,
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
}

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

pub fn iterate_dump_whole_state<F: Fn(AccountState)>(
    conf: &mut Configuration, exit_cond_var: Arc<(Mutex<bool>, Condvar)>,
    config: &StateDumpConfig, callback: F,
) -> Result<H256, String> {
    let (mut state_db, state_root) =
        prepare_state_db(conf, exit_cond_var, config)?;

    export_space_accounts_with_iterator(
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
    println!("Preparing state...");
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
                println!("Find account: {:?}", address);
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
                println!("no-contract account have code: {:?}", code);
            }
            None
        };

        let storage = if is_contract {
            storage_map.get(&address).cloned()
        } else {
            if let Some(storage) = storage_map.get(&address) {
                println!("no-contract account have storage: {:?}", storage);
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

fn export_space_accounts_with_iterator<F: Fn(AccountState)>(
    state: &mut StateDbGeneric, space: Space, config: &StateDumpConfig,
    callback: F,
) -> Result<(), Box<dyn std::error::Error>> {
    let empty_key = StorageKey::EmptyKey.with_space(space);
    let (kvs, maybe_kv_iterator) = state.read_all_iterator(empty_key)?;

    let mut deleted_keys = HashSet::new();
    let mut found_accounts = 0;

    // Iterate key value pairs from delta trie and intermediate trie
    for (k, v) in kvs {
        let storage_key = StorageKeyWithSpace::from_delta_mpt_key(&k);
        let key = storage_key.to_key_bytes();
        deleted_keys.insert(key.clone());

        let storage_key_with_space =
            StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key);
        if storage_key_with_space.space != space {
            continue;
        }

        if let StorageKey::AccountKey(address_bytes) =
            storage_key_with_space.key
        {
            let address = Address::from_slice(address_bytes);
            println!("Find account: {:?}", address);
            let account = Account::new_from_rlp(address, &Rlp::new(&v))?;

            let account_state = get_account_state(state, &account, config)?;
            callback(account_state);
            found_accounts += 1;

            if config.limit > 0 && found_accounts >= config.limit as usize {
                break;
            }
        } else {
            continue;
        }
    }

    let lower_bound_incl = empty_key.to_key_bytes();
    let upper_bound_excl = to_key_prefix_iter_upper_bound(&lower_bound_incl);

    if let Some(mut kv_iterator) = maybe_kv_iterator {
        let mut kvs = kv_iterator
            .iter_range(
                lower_bound_incl.as_slice(),
                upper_bound_excl.as_ref().map(|v| &**v),
            )?
            .take();

        while let Some((key, value)) = kvs.next()? {
            if deleted_keys.contains(&key) {
                continue;
            }

            let storage_key_with_space =
                StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key);
            if storage_key_with_space.space != space {
                continue;
            }

            if let StorageKey::AccountKey(address_bytes) =
                storage_key_with_space.key
            {
                let address = Address::from_slice(address_bytes);
                println!("Find account: {:?}", address);
                let account =
                    Account::new_from_rlp(address, &Rlp::new(&value))?;

                let account_state = get_account_state(state, &account, config)?;
                callback(account_state);
                found_accounts += 1;

                if config.limit > 0 && found_accounts >= config.limit as usize {
                    break;
                }
            } else {
                continue;
            }
        }
    }

    Ok(())
}

#[allow(unused)]
fn get_account_state(
    state: &mut StateDbGeneric, account: &Account, config: &StateDumpConfig,
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
        let storage = state.get_account_storage_entries(&address, None)?;
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
