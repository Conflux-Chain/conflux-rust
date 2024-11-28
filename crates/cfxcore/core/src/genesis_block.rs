// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    sync::Arc,
};

use rustc_hex::FromHex;
use serde::{Deserialize, Serialize};
use toml::Value;

use cfx_executor::internal_contract::initialize_internal_contract_accounts;
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::{
    consensus::{GENESIS_GAS_LIMIT, ONE_CFX_IN_DRIP},
    consensus_internal::{
        GENESIS_TOKEN_COUNT_IN_CFX, TWO_YEAR_UNLOCK_TOKEN_COUNT_IN_CFX,
    },
    genesis::*,
    staking::POS_VOTE_PRICE,
};
use cfx_statedb::StateDb;
use cfx_storage::{StorageManager, StorageManagerTrait};
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, H256, U256,
};
use diem_crypto::{
    bls::BLSPrivateKey, ec_vrf::EcVrfPublicKey, PrivateKey, ValidCryptoMaterial,
};
use diem_types::validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey};
use keylib::KeyPair;
use primitives::{
    Action, Block, BlockHeaderBuilder, BlockReceipts, SignedTransaction,
};
use secret_store::SecretStore;

use crate::verification::{compute_receipts_root, compute_transaction_root};
use cfx_executor::{
    executive::{
        contract_address, ExecutionOutcome, ExecutiveContext, TransactOptions,
    },
    machine::Machine,
    state::{CleanupMode, State},
};
use cfx_vm_types::{CreateContractAddress, Env};
use diem_types::account_address::AccountAddress;
use primitives::transaction::native_transaction::NativeTransaction;

pub fn default(dev_or_test_mode: bool) -> HashMap<AddressWithSpace, U256> {
    if !dev_or_test_mode {
        return HashMap::new();
    }
    let mut accounts: HashMap<AddressWithSpace, U256> = HashMap::new();
    // FIXME: Decide the genesis initialization for mainnet.
    let balance = U256::from_dec_str("5000000000000000000000000000000000")
        .expect("Not overflow"); // 5*10^33
    accounts
        .insert(DEV_GENESIS_KEY_PAIR.address().with_native_space(), balance);
    accounts.insert(
        DEV_GENESIS_KEY_PAIR_2.address().with_native_space(),
        balance,
    );
    accounts
        .insert(DEV_GENESIS_KEY_PAIR.evm_address().with_evm_space(), balance);
    accounts.insert(
        DEV_GENESIS_KEY_PAIR_2.evm_address().with_evm_space(),
        balance,
    );
    accounts
}

pub fn load_secrets_file(
    path: &String, secret_store: &SecretStore, space: Space,
) -> Result<HashMap<AddressWithSpace, U256>, String> {
    let file = File::open(path)
        .map_err(|e| format!("failed to open file: {:?}", e))?;
    let buffered = BufReader::new(file);

    let mut accounts: HashMap<AddressWithSpace, U256> = HashMap::new();
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

        match space {
            Space::Native => {
                // Insert balance for native space only
                accounts.insert(
                    keypair.address().with_native_space(),
                    balance.clone(),
                );
            }
            Space::Ethereum => {
                // Insert balance for EVM space only
                accounts.insert(
                    keypair.evm_address().with_evm_space(),
                    balance.clone(),
                );
            }
        }

        secret_store.insert(keypair);
    }
    Ok(accounts)
}

/// ` test_net_version` is used to update the genesis author so that after
/// resetting, the chain of the older version will be discarded
pub fn genesis_block(
    storage_manager: &Arc<StorageManager>,
    genesis_accounts: HashMap<AddressWithSpace, U256>,
    test_net_version: Address, initial_difficulty: U256, machine: Arc<Machine>,
    need_to_execute: bool, genesis_chain_id: Option<u32>,
    initial_nodes: &Option<GenesisPosState>,
) -> Block {
    let mut state =
        State::new(StateDb::new(storage_manager.get_state_for_genesis_write()))
            .expect("Failed to initialize state");

    let mut genesis_block_author = test_net_version;
    genesis_block_author.set_user_account_type_bits();

    initialize_internal_contract_accounts(
        &mut state,
        machine.internal_contracts().initialized_at_genesis(),
    )
    .expect("no db error");
    trace!("genesis_accounts: {:?}", genesis_accounts);
    for (addr, balance) in genesis_accounts {
        state
            .add_balance(&addr, &balance, CleanupMode::NoEmpty)
            .unwrap();
        state.add_total_issued(balance);
        if addr.space == Space::Ethereum {
            state.add_total_evm_tokens(balance);
        }
    }
    let genesis_account_address = GENESIS_ACCOUNT_ADDRESS.with_native_space();

    let genesis_token_count =
        U256::from(GENESIS_TOKEN_COUNT_IN_CFX) * U256::from(ONE_CFX_IN_DRIP);
    state.add_total_issued(genesis_token_count);
    let two_year_unlock_token_count =
        U256::from(TWO_YEAR_UNLOCK_TOKEN_COUNT_IN_CFX)
            * U256::from(ONE_CFX_IN_DRIP);
    let four_year_unlock_token_count =
        genesis_token_count - two_year_unlock_token_count;

    let genesis_account_init_balance =
        U256::from(ONE_CFX_IN_DRIP) * 100 + genesis_token_count;
    state
        .add_balance(
            &genesis_account_address,
            &genesis_account_init_balance,
            CleanupMode::NoEmpty,
        )
        .unwrap();

    let mut debug_record = Some(ComputeEpochDebugRecord::default());

    let genesis_chain_id = genesis_chain_id.unwrap_or(0);
    let mut genesis_transaction = NativeTransaction::default();
    genesis_transaction.data = GENESIS_TRANSACTION_DATA_STR.as_bytes().into();
    genesis_transaction.action = Action::Call(Default::default());
    genesis_transaction.chain_id = genesis_chain_id;

    let mut create_create2factory_transaction = NativeTransaction::default();
    create_create2factory_transaction.nonce = 0.into();
    create_create2factory_transaction.data =
        GENESIS_TRANSACTION_CREATE_CREATE2FACTORY
            .from_hex()
            .unwrap();
    create_create2factory_transaction.action = Action::Create;
    create_create2factory_transaction.chain_id = genesis_chain_id;
    create_create2factory_transaction.gas = 300000.into();
    create_create2factory_transaction.gas_price = 1.into();
    create_create2factory_transaction.storage_limit = 512;

    let mut create_genesis_token_manager_two_year_unlock_transaction =
        NativeTransaction::default();
    create_genesis_token_manager_two_year_unlock_transaction.nonce = 1.into();
    create_genesis_token_manager_two_year_unlock_transaction.data =
        GENESIS_TRANSACTION_CREATE_GENESIS_TOKEN_MANAGER_TWO_YEAR_UNLOCK
            .from_hex()
            .unwrap();
    create_genesis_token_manager_two_year_unlock_transaction.value =
        two_year_unlock_token_count;
    create_genesis_token_manager_two_year_unlock_transaction.action =
        Action::Create;
    create_genesis_token_manager_two_year_unlock_transaction.chain_id =
        genesis_chain_id;
    create_genesis_token_manager_two_year_unlock_transaction.gas =
        2800000.into();
    create_genesis_token_manager_two_year_unlock_transaction.gas_price =
        1.into();
    create_genesis_token_manager_two_year_unlock_transaction.storage_limit =
        16000;

    let mut create_genesis_token_manager_four_year_unlock_transaction =
        NativeTransaction::default();
    create_genesis_token_manager_four_year_unlock_transaction.nonce = 2.into();
    create_genesis_token_manager_four_year_unlock_transaction.data =
        GENESIS_TRANSACTION_CREATE_GENESIS_TOKEN_MANAGER_FOUR_YEAR_UNLOCK
            .from_hex()
            .unwrap();
    create_genesis_token_manager_four_year_unlock_transaction.value =
        four_year_unlock_token_count;
    create_genesis_token_manager_four_year_unlock_transaction.action =
        Action::Create;
    create_genesis_token_manager_four_year_unlock_transaction.chain_id =
        genesis_chain_id;
    create_genesis_token_manager_four_year_unlock_transaction.gas =
        5000000.into();
    create_genesis_token_manager_four_year_unlock_transaction.gas_price =
        1.into();
    create_genesis_token_manager_four_year_unlock_transaction.storage_limit =
        32000;

    let mut create_genesis_investor_fund_transaction =
        NativeTransaction::default();
    create_genesis_investor_fund_transaction.nonce = 3.into();
    create_genesis_investor_fund_transaction.data =
        GENESIS_TRANSACTION_CREATE_FUND_POOL.from_hex().unwrap();
    create_genesis_investor_fund_transaction.action = Action::Create;
    create_genesis_investor_fund_transaction.chain_id = genesis_chain_id;
    create_genesis_investor_fund_transaction.gas = 400000.into();
    create_genesis_investor_fund_transaction.gas_price = 1.into();
    create_genesis_investor_fund_transaction.storage_limit = 1000;

    let mut create_genesis_team_fund_transaction = NativeTransaction::default();
    create_genesis_team_fund_transaction.nonce = 4.into();
    create_genesis_team_fund_transaction.data =
        GENESIS_TRANSACTION_CREATE_FUND_POOL.from_hex().unwrap();
    create_genesis_team_fund_transaction.action = Action::Create;
    create_genesis_team_fund_transaction.chain_id = genesis_chain_id;
    create_genesis_team_fund_transaction.gas = 400000.into();
    create_genesis_team_fund_transaction.gas_price = 1.into();
    create_genesis_team_fund_transaction.storage_limit = 1000;

    let mut create_genesis_eco_fund_transaction = NativeTransaction::default();
    create_genesis_eco_fund_transaction.nonce = 5.into();
    create_genesis_eco_fund_transaction.data =
        GENESIS_TRANSACTION_CREATE_FUND_POOL.from_hex().unwrap();
    create_genesis_eco_fund_transaction.action = Action::Create;
    create_genesis_eco_fund_transaction.chain_id = genesis_chain_id;
    create_genesis_eco_fund_transaction.gas = 400000.into();
    create_genesis_eco_fund_transaction.gas_price = 1.into();
    create_genesis_eco_fund_transaction.storage_limit = 1000;

    let mut create_genesis_community_fund_transaction =
        NativeTransaction::default();
    create_genesis_community_fund_transaction.nonce = 6.into();
    create_genesis_community_fund_transaction.data =
        GENESIS_TRANSACTION_CREATE_FUND_POOL.from_hex().unwrap();
    create_genesis_community_fund_transaction.action = Action::Create;
    create_genesis_community_fund_transaction.chain_id = genesis_chain_id;
    create_genesis_community_fund_transaction.gas = 400000.into();
    create_genesis_community_fund_transaction.gas_price = 1.into();
    create_genesis_community_fund_transaction.storage_limit = 1000;

    let genesis_transactions = vec![
        Arc::new(genesis_transaction.fake_sign(Default::default())),
        Arc::new(
            create_create2factory_transaction
                .fake_sign(genesis_account_address),
        ),
        Arc::new(
            create_genesis_token_manager_two_year_unlock_transaction
                .fake_sign(genesis_account_address),
        ),
        Arc::new(
            create_genesis_token_manager_four_year_unlock_transaction
                .fake_sign(genesis_account_address),
        ),
        Arc::new(
            create_genesis_investor_fund_transaction
                .fake_sign(genesis_account_address),
        ),
        Arc::new(
            create_genesis_team_fund_transaction
                .fake_sign(genesis_account_address),
        ),
        Arc::new(
            create_genesis_eco_fund_transaction
                .fake_sign(genesis_account_address),
        ),
        Arc::new(
            create_genesis_community_fund_transaction
                .fake_sign(genesis_account_address),
        ),
    ];

    if need_to_execute {
        const CREATE2FACTORY_TX_INDEX: usize = 1;
        /*
        const TWO_YEAR_UNLOCK_TX_INDEX: usize = 2;
        const FOUR_YEAR_UNLOCK_TX_INDEX: usize = 3;
        const INVESTOR_FUND_TX_INDEX: usize = 4;
        const TEAM_FUND_TX_INDEX: usize = 5;
        const ECO_FUND_TX_INDEX: usize = 6;
        const COMMUNITY_FUND_TX_INDEX: usize = 7;
        */
        let contract_name_list = vec![
            "CREATE2FACTORY",
            "TWO_YEAR_UNLOCK",
            "FOUR_YEAR_UNLOCK",
            "INVESTOR_FUND",
            "TEAM_FUND",
            "ECO_FUND",
            "COMMUNITY_FUND",
        ];

        for i in CREATE2FACTORY_TX_INDEX..=contract_name_list.len() {
            execute_genesis_transaction(
                genesis_transactions[i].as_ref(),
                &mut state,
                machine.clone(),
            );

            let (contract_address, _) = contract_address(
                CreateContractAddress::FromSenderNonceAndCodeHash,
                0,
                &genesis_account_address,
                &(i - 1).into(),
                genesis_transactions[i].as_ref().data(),
            );

            state
                .set_admin(&contract_address.address, &Address::zero())
                .expect("");
            info!(
                "Genesis {:?} addresses: {:?}",
                contract_name_list[i - 1],
                contract_address
            );
        }
    }

    if let Some(initial_nodes) = initial_nodes {
        for node in &initial_nodes.initial_nodes {
            let stake_balance = U256::from(node.voting_power) * *POS_VOTE_PRICE;
            // TODO(lpl): Pass in signed tx so they can be retired.
            state
                .add_balance(
                    &node.address.with_native_space(),
                    &(stake_balance
                        + U256::from(ONE_CFX_IN_DRIP) * U256::from(20)),
                    CleanupMode::NoEmpty,
                )
                .unwrap();
            state
                .deposit(&node.address, &stake_balance, 0, false)
                .unwrap();
            let signed_tx = node
                .register_tx
                .clone()
                .fake_sign(node.address.with_native_space());
            execute_genesis_transaction(
                &signed_tx,
                &mut state,
                machine.clone(),
            );
        }
    }

    state
        .genesis_special_remove_account(&genesis_account_address.address)
        .expect("Clean account failed");

    let state_root = state
        .compute_state_root_for_genesis(
            /* debug_record = */ debug_record.as_mut(),
        )
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

pub fn register_transaction(
    bls_priv_key: BLSPrivateKey, vrf_pub_key: EcVrfPublicKey, power: u64,
    genesis_chain_id: u32, legacy: bool,
) -> NativeTransaction {
    /// TODO: test this function with new internal contracts.
    use bls_signatures::{
        sigma_protocol, PrivateKey as BlsPrivKey, PublicKey as BlsPubKey,
        Serialize,
    };
    use cfx_parameters::internal_contract_addresses::POS_REGISTER_CONTRACT_ADDRESS;
    use rand_08::rngs::OsRng;
    use solidity_abi::ABIEncodable;
    use tiny_keccak::{Hasher, Keccak};

    let bls_pub_key = bls_priv_key.public_key();
    let (commit, answer) =
        sigma_protocol::prove(bls_priv_key.raw_key(), &mut OsRng, legacy);

    let mut encoded_commit = Vec::<u8>::new();
    BlsPubKey::from(commit)
        .write_bytes(&mut encoded_commit)
        .expect("write to Vec<u8> never fails");

    let mut encoded_answer = Vec::<u8>::new();
    BlsPrivKey::from(answer)
        .write_bytes(&mut encoded_answer)
        .expect("write to Vec<u8> never fails");

    let encoded_bls_pub_key = bls_pub_key.to_bytes();

    let encoded_vrf_pub_key = vrf_pub_key.to_bytes();

    let mut hasher = Keccak::v256();
    hasher.update(encoded_bls_pub_key.as_slice());
    hasher.update(encoded_vrf_pub_key.as_slice());
    let mut computed_identifier = H256::default();
    hasher.finalize(computed_identifier.as_bytes_mut());

    let params = (
        computed_identifier,
        power,
        encoded_bls_pub_key,
        encoded_vrf_pub_key,
        [encoded_commit, encoded_answer],
    );

    let mut call_data: Vec<u8> = "e335b451".from_hex().unwrap();
    call_data.extend_from_slice(&params.abi_encode());

    let mut tx = NativeTransaction::default();
    tx.nonce = 0.into();
    tx.data = call_data;
    tx.value = U256::zero();
    tx.action = Action::Call(POS_REGISTER_CONTRACT_ADDRESS);
    tx.chain_id = genesis_chain_id;
    tx.gas = 200000.into();
    tx.gas_price = 1.into();
    tx.storage_limit = 16000;
    tx
}

fn execute_genesis_transaction(
    transaction: &SignedTransaction, state: &mut State, machine: Arc<Machine>,
) {
    let env = Env::default();

    let options = TransactOptions::default();
    let r = {
        ExecutiveContext::new(
            state,
            &env,
            machine.as_ref(),
            &machine.spec(env.number, env.epoch_height),
        )
        .transact(transaction, options)
        .unwrap()
    };

    match &r {
        ExecutionOutcome::Finished(_executed) => {}
        _ => {
            panic!("genesis transaction should not fail! err={:?}", r);
        }
    }
}

pub fn load_file(
    path: &String, address_parser: impl Fn(&str) -> Result<Address, String>,
) -> Result<HashMap<AddressWithSpace, U256>, String> {
    let mut content = String::new();
    let mut file = File::open(path)
        .map_err(|e| format!("failed to open file: {:?}", e))?;
    file.read_to_string(&mut content)
        .map_err(|e| format!("failed to read file content: {:?}", e))?;
    let account_values = content
        .parse::<toml::Value>()
        .map_err(|e| format!("failed to parse toml file: {:?}", e))?;

    let mut accounts: HashMap<AddressWithSpace, U256> = HashMap::new();
    match account_values {
        Value::Table(table) => {
            for (key, value) in table {
                let addr = address_parser(&key).map_err(|e| {
                    format!(
                        "failed to parse address: value = {}, error = {:?}",
                        key, e
                    )
                })?;

                match value {
                    Value::String(balance) => {
                        let balance = U256::from_dec_str(&balance).map_err(|e| format!("failed to parse balance: value = {}, error = {:?}", balance, e))?;
                        accounts.insert(addr.with_native_space(), balance);
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

#[derive(Serialize, Deserialize, Clone)]
pub struct GenesisPosNodeInfo {
    pub address: Address,
    pub bls_key: ConsensusPublicKey,
    pub vrf_key: ConsensusVRFPublicKey,
    pub voting_power: u64,
    pub register_tx: NativeTransaction,
}

#[derive(Serialize, Deserialize)]
pub struct GenesisPosState {
    pub initial_nodes: Vec<GenesisPosNodeInfo>,
    pub initial_committee: Vec<(AccountAddress, u64)>,
    pub initial_seed: H256,
}
