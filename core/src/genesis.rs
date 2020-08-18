// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    consensus::debug::ComputeEpochDebugRecord,
    evm::Spec,
    executive::InternalContractMap,
    parameters::consensus::GENESIS_GAS_LIMIT,
    state::{CleanupMode, State},
    statedb::{Result as DbResult, StateDb},
    storage::{StorageManager, StorageManagerTrait},
    verification::{compute_receipts_root, compute_transaction_root},
};
use cfx_types::{address_util::AddressUtil, Address, U256};
use keylib::KeyPair;
use primitives::{
    storage::STORAGE_LAYOUT_REGULAR_V0, Action, Block, BlockHeaderBuilder,
    BlockReceipts, Transaction,
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
pub const GENESIS_TRANSACTION_DATA_STR: &'static str = "
26870.10643898104687425822313361.30
Cogito ergo sum. - René Descartes";

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

pub fn initialize_internal_contract_accounts(state: &mut State) {
    || -> DbResult<()> {
        {
            for address in InternalContractMap::new().keys() {
                state.new_contract_with_admin(
                    address,
                    /* No admin; admin = */ &Address::zero(),
                    /* balance = */ U256::zero(),
                    state.contract_start_nonce(),
                    Some(STORAGE_LAYOUT_REGULAR_V0),
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
    storage_manager: &Arc<StorageManager>,
    genesis_accounts: HashMap<Address, U256>, test_net_version: Address,
    initial_difficulty: U256,
) -> Block
{
    let mut state = State::new(
        StateDb::new(storage_manager.get_state_for_genesis_write()),
        Default::default(),
        &Spec::new_spec(),
        0, /* block_number */
    );
    let mut genesis_block_author = test_net_version;
    genesis_block_author.set_user_account_type_bits();

    let mut total_balance = U256::from(0);
    initialize_internal_contract_accounts(&mut state);
    for (addr, balance) in genesis_accounts {
        state
            .add_balance(&addr, &balance, CleanupMode::NoEmpty)
            .unwrap();
        total_balance += balance;
    }
    state.add_total_issued(total_balance);

    let mut debug_record = Some(ComputeEpochDebugRecord::default());
    let state_root = state
        .compute_state_root(/* debug_record = */ debug_record.as_mut())
        .unwrap();
    let receipt_root = compute_receipts_root(&vec![Arc::new(BlockReceipts {
        receipts: vec![],
        secondary_reward: U256::zero(),
    })]);
    let mut genesis_transaction = Transaction::default();
    genesis_transaction.data = GENESIS_TRANSACTION_DATA_STR.as_bytes().into();
    genesis_transaction.action = Action::Call(Default::default());
    genesis_transaction.chain_id = 2; // Genesis transaction for Oceanus.
    let genesis_transactions =
        vec![Arc::new(genesis_transaction.fake_sign(Default::default()))];
    let mut genesis = Block::new(
        BlockHeaderBuilder::new()
            .with_deferred_state_root(state_root.aux_info.state_root_hash)
            .with_deferred_receipts_root(receipt_root)
            .with_gas_limit(GENESIS_GAS_LIMIT.into())
            .with_author(genesis_block_author)
            .with_difficulty(initial_difficulty)
            .with_transactions_root(compute_transaction_root(
                &genesis_transactions,
            ))
            .build(),
        genesis_transactions,
    );
    genesis.block_header.compute_hash();
    debug!(
        "Initialize genesis_block={:?} hash={:?}",
        genesis,
        genesis.hash()
    );
    state
        .commit(
            genesis.block_header.hash(),
            /* debug_record = */ debug_record.as_mut(),
        )
        .unwrap();
    genesis.block_header.pow_hash = Some(Default::default());
    debug!(
        "genesis debug_record {}",
        serde_json::to_string(&debug_record).unwrap()
    );
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
