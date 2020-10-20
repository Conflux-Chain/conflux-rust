// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    evm::Spec,
    executive::{
        contract_address, ExecutionOutcome, Executive, InternalContractMap,
    },
    machine::Machine,
    state::{CleanupMode, State},
    verification::{compute_receipts_root, compute_transaction_root},
    vm::{CreateContractAddress, Env},
};
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::consensus::{GENESIS_GAS_LIMIT, ONE_CFX_IN_DRIP};
use cfx_statedb::{Result as DbResult, StateDb};
use cfx_storage::{StorageManager, StorageManagerTrait};
use cfx_types::{address_util::AddressUtil, Address, U256};
use hex::FromHex;
use keylib::KeyPair;
use parity_bytes::Bytes;
use primitives::{
    storage::STORAGE_LAYOUT_REGULAR_V0, Action, Block, BlockHeaderBuilder,
    BlockReceipts, SignedTransaction, Transaction,
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

pub const GENESIS_TRANSACTION_CREATE_CREATE2FACTORY: &'static str = "608060405234801561001057600080fd5b506102a2806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c806390184b021461003b5780639c4ae2d014610075575b600080fd5b6100616004803603602081101561005157600080fd5b50356001600160a01b0316610139565b604080519115158252519081900360200190f35b61011d6004803603604081101561008b57600080fd5b8101906020810181356401000000008111156100a657600080fd5b8201836020820111156100b857600080fd5b803590602001918460018302840111640100000000831117156100da57600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295505091359250610157915050565b604080516001600160a01b039092168252519081900360200190f35b6001600160a01b031660009081526020819052604090205460ff1690565b600080600060019050838551602087016000f59150813b610176575060005b806101c8576040805162461bcd60e51b815260206004820152600e60248201527f63726561746532206661696c6564000000000000000000000000000000000000604482015290519081900360640190fd5b6001600160a01b03821660009081526020819052604090205460ff16156102205760405162461bcd60e51b815260040180806020018281038252602181526020018061024d6021913960400191505060405180910390fd5b506001600160a01b0381166000908152602081905260409020805460ff1916600117905590509291505056fe636f6e747261637420686173206265656e206465706c6f796564206265666f7265a265627a7a723158200af37f6335cc41d7dfae2771f8663b4a48fc54c11ec8a28682901a0951f9ce5364736f6c634300050b0032";

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
    initial_difficulty: U256, machine: Arc<Machine>, need_to_execute: bool,
    genesis_chain_id: Option<u32>,
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

    let genesis_account_address = "1949000000000000000000000000000000001001"
        .parse::<Address>()
        .unwrap();

    let genesis_account_init_balance = U256::from(ONE_CFX_IN_DRIP);
    state
        .add_balance(
            &genesis_account_address,
            &genesis_account_init_balance,
            CleanupMode::NoEmpty,
        )
        .unwrap();

    let mut debug_record = Some(ComputeEpochDebugRecord::default());

    let genesis_chain_id = genesis_chain_id.unwrap_or(0);
    let mut genesis_transaction = Transaction::default();
    genesis_transaction.data = GENESIS_TRANSACTION_DATA_STR.as_bytes().into();
    genesis_transaction.action = Action::Call(Default::default());
    genesis_transaction.chain_id = genesis_chain_id; // Genesis transaction for Oceanus.

    let mut create_create2factory_transaction = Transaction::default();
    create_create2factory_transaction.data =
        Bytes::from_hex(GENESIS_TRANSACTION_CREATE_CREATE2FACTORY).unwrap();
    create_create2factory_transaction.action = Action::Create;
    create_create2factory_transaction.chain_id = genesis_chain_id;
    create_create2factory_transaction.gas = 300000.into();
    create_create2factory_transaction.gas_price = 1.into();
    create_create2factory_transaction.storage_limit = 512;

    let genesis_transactions = vec![
        Arc::new(genesis_transaction.fake_sign(Default::default())),
        Arc::new(
            create_create2factory_transaction
                .fake_sign(genesis_account_address),
        ),
    ];

    if need_to_execute {
        execute_genesis_transaction(
            genesis_transactions[1].as_ref(),
            &mut state,
            machine.clone(),
        );

        let (create2factory_contract_address, _) = contract_address(
            CreateContractAddress::FromSenderNonceAndCodeHash,
            0.into(),
            &genesis_account_address,
            &U256::zero(),
            &genesis_transactions[1].as_ref().data,
        );
        state
            .set_admin(
                &genesis_account_address,
                &create2factory_contract_address,
                &Address::zero(),
            )
            .expect("");
    }
    state.clean_account(&genesis_account_address);

    let state_root = state
        .compute_state_root(/* debug_record = */ debug_record.as_mut())
        .unwrap();
    let receipt_root = compute_receipts_root(&vec![Arc::new(BlockReceipts {
        receipts: vec![],
        block_number: 0,
        secondary_reward: U256::zero(),
        tx_execution_error_messages: vec![],
    })]);

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

fn execute_genesis_transaction(
    transaction: &SignedTransaction, state: &mut State, machine: Arc<Machine>,
) {
    let env = Env::default();
    let spec = Spec::new_spec();
    let internal_contract_map = InternalContractMap::new();

    let r = {
        Executive::new(
            state,
            &env,
            machine.as_ref(),
            &spec,
            &internal_contract_map,
        )
        .transact(transaction)
        .unwrap()
    };

    match r {
        ExecutionOutcome::Finished(_executed) => {}
        _ => {
            panic!("genesis transaction should not fail!");
        }
    }
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
