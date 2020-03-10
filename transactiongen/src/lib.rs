// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate cfx_bytes as bytes;
extern crate core;
extern crate ethkey as keylib;
extern crate network;
extern crate parking_lot;
extern crate primitives;
extern crate rand;
extern crate secret_store;
#[macro_use]
extern crate log;

use crate::bytes::Bytes;
use cfx_types::{Address, BigEndianHash, H256, H512, U256, U512};
use cfxcore::{
    executive::contract_address, vm::CreateContractAddress,
    SharedConsensusGraph, SharedSynchronizationService, SharedTransactionPool,
};
use hex::FromHex;
use keylib::{public_to_address, Generator, KeyPair, Random, Secret};
use lazy_static::lazy_static;
use metrics::{register_meter_with_group, Meter};
use parity_bytes::ToPretty;
use parking_lot::RwLock;
use primitives::{
    transaction::Action, Account, SignedTransaction, Transaction,
};
use rand::prelude::*;
use rlp::Encodable;
use secret_store::SharedSecretStore;
use std::{
    cmp::Ordering,
    collections::HashMap,
    convert::TryFrom,
    sync::Arc,
    thread,
    time::{self, Instant},
};
use time::Duration;

pub mod propagate;

lazy_static! {
    static ref TX_GEN_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "tx_gen");
}

enum TransGenState {
    Start,
    Stop,
}

pub struct TransactionGeneratorConfig {
    pub generate_tx: bool,
    pub period: time::Duration,
    pub account_count: usize,
}

impl TransactionGeneratorConfig {
    pub fn new(
        generate_tx: bool, period_ms: u64, account_count: usize,
    ) -> Self {
        TransactionGeneratorConfig {
            generate_tx,
            period: time::Duration::from_micros(period_ms),
            account_count,
        }
    }
}

pub struct TransactionGenerator {
    consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    txpool: SharedTransactionPool,
    secret_store: SharedSecretStore,
    state: RwLock<TransGenState>,
    account_start_index: RwLock<Option<usize>>,
    join_handle: RwLock<Option<thread::JoinHandle<()>>>,
}

pub type SharedTransactionGenerator = Arc<TransactionGenerator>;

impl TransactionGenerator {
    // FIXME: rename to start and return Result<Self>
    pub fn new(
        consensus: SharedConsensusGraph, txpool: SharedTransactionPool,
        sync: SharedSynchronizationService, secret_store: SharedSecretStore,
    ) -> Self
    {
        TransactionGenerator {
            consensus,
            txpool,
            sync,
            secret_store,
            state: RwLock::new(TransGenState::Start),
            account_start_index: RwLock::new(Option::None),
            join_handle: RwLock::new(None),
        }
    }

    pub fn stop(&self) {
        *self.state.write() = TransGenState::Stop;
        if let Some(join_handle) = self.join_handle.write().take() {
            join_handle.join().ok();
        }
    }

    pub fn set_genesis_accounts_start_index(&self, index: usize) {
        let mut account_start = self.account_start_index.write();
        *account_start = Some(index);
    }

    pub fn set_join_handle(&self, join_handle: thread::JoinHandle<()>) {
        self.join_handle.write().replace(join_handle);
    }

    pub fn generate_transactions_with_multiple_genesis_accounts(
        txgen: Arc<TransactionGenerator>, tx_config: TransactionGeneratorConfig,
    ) {
        loop {
            let account_start = txgen.account_start_index.read();
            if account_start.is_some() {
                break;
            }
        }
        let account_start_index = txgen.account_start_index.read().unwrap();
        let mut nonce_map: HashMap<Address, U256> = HashMap::new();
        let mut balance_map: HashMap<Address, U256> = HashMap::new();
        let mut address_secret_pair: HashMap<Address, Secret> = HashMap::new();
        let mut addresses: Vec<Address> = Vec::new();

        debug!("Tx Generation Config {:?}", tx_config.generate_tx);

        let mut tx_n = 0;
        // Wait for initial tx
        loop {
            match *txgen.state.read() {
                TransGenState::Stop => return,
                _ => {}
            }

            // Do not generate tx in catch_up_mode
            if txgen.sync.catch_up_mode() {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            break;
        }

        debug!("Setup Usable Genesis Accounts");
        let state = txgen.consensus.get_best_state();
        for i in 0..tx_config.account_count {
            let key_pair =
                txgen.secret_store.get_keypair(account_start_index + i);
            let address = key_pair.address();
            let secret = key_pair.secret().clone();
            addresses.push(address);
            nonce_map.insert(address.clone(), 0.into());

            let balance = state.balance(&address).ok();

            balance_map.insert(address.clone(), balance.unwrap());
            address_secret_pair.insert(address, secret);
        }
        // State cache can be large
        drop(state);

        info!("Start Generating Workload");
        let start_time = Instant::now();
        // Generate more tx

        let account_count = address_secret_pair.len();
        loop {
            match *txgen.state.read() {
                TransGenState::Stop => return,
                _ => {}
            }

            // Randomly select sender and receiver.
            // Sender and receiver must exist in the account list.
            let mut receiver_index: usize = random();
            receiver_index %= account_count;
            let receiver_address = addresses[receiver_index];

            let mut sender_index: usize = random();
            sender_index %= account_count;
            let sender_address = addresses[sender_index];

            // Always send value 0
            let balance_to_transfer = U256::from(0);

            // Generate nonce for the transaction
            let sender_nonce = nonce_map.get_mut(&sender_address).unwrap();

            // FIXME: It's better first define what kind of Result type
            // FIXME: to use for this function, then change unwrap() to ?.
            let (nonce, balance) = txgen
                .txpool
                .get_state_account_info(&sender_address)
                .unwrap();
            if nonce.cmp(sender_nonce) != Ordering::Equal {
                *sender_nonce = nonce.clone();
                balance_map.insert(sender_address.clone(), balance.clone());
            }
            trace!(
                "receiver={:?} value={:?} nonce={:?}",
                receiver_address,
                balance_to_transfer,
                sender_nonce
            );
            // Generate the transaction, sign it, and push into the transaction
            // pool
            let tx = Transaction {
                nonce: *sender_nonce,
                gas_price: U256::from(1u64),
                gas: U256::from(21000u64),
                value: balance_to_transfer,
                action: Action::Call(receiver_address),
                storage_limit: U256::MAX,
                data: Bytes::new(),
            };

            let signed_tx = tx.sign(&address_secret_pair[&sender_address]);
            let mut tx_to_insert = Vec::new();
            tx_to_insert.push(signed_tx.transaction);
            let (txs, fail) =
                txgen.txpool.insert_new_transactions(tx_to_insert);
            if fail.is_empty() {
                txgen.sync.append_received_transactions(txs);
                //tx successfully inserted into
                // tx pool, so we can update our state about
                // nonce and balance
                {
                    let sender_balance =
                        balance_map.get_mut(&sender_address).unwrap();
                    *sender_balance -= balance_to_transfer + 21000;
                    if *sender_balance < 42000.into() {
                        addresses.remove(sender_index);
                        if addresses.is_empty() {
                            break;
                        }
                    }
                }
                *sender_nonce += U256::one();
                *balance_map.entry(receiver_address).or_insert(0.into()) +=
                    balance_to_transfer;
                tx_n += 1;
                TX_GEN_METER.mark(1);
            } else {
                // The transaction pool is full and the tx is discarded, so the
                // state should not updated. We add unconditional
                // sleep to avoid busy spin if the tx pool cannot support the
                // expected throughput.
                thread::sleep(tx_config.period);
            }

            let now = Instant::now();
            let time_elapsed = now.duration_since(start_time);
            if let Some(time_left) =
                (tx_config.period * tx_n).checked_sub(time_elapsed)
            {
                thread::sleep(time_left);
            } else {
                debug!("Elapsed time larger than the time needed for sleep: time_elapsed={:?}", time_elapsed);
            }
        }
    }
}

/// This tx generator directly push simple transactions and erc20 transactions
/// into blocks. It's used in Ethereum e2d replay test.
pub struct DirectTransactionGenerator {
    // Key, simple tx, erc20 balance, array index.
    accounts: HashMap<Address, (KeyPair, Account, U256)>,
    address_by_index: Vec<Address>,
    erc20_address: Address,
}

// Allow use of hex() in H256, etc.
#[allow(deprecated)]
impl DirectTransactionGenerator {
    const MAX_TOTAL_ACCOUNTS: usize = 100_000;

    pub fn new(
        start_key_pair: KeyPair, contract_creator: &Address,
        start_balance: U256, start_erc20_balance: U256,
    ) -> DirectTransactionGenerator
    {
        let start_address = public_to_address(start_key_pair.public());
        let info = (
            start_key_pair,
            Account::new_empty_with_balance(
                &start_address,
                &start_balance,
                &0.into(), /* nonce */
            ),
            start_erc20_balance,
        );
        let mut accounts = HashMap::<Address, (KeyPair, Account, U256)>::new();
        accounts.insert(start_address.clone(), info);
        let address_by_index = vec![start_address.clone()];

        let erc20_address = contract_address(
            CreateContractAddress::FromSenderAndNonce,
            &contract_creator,
            &0.into(),
            &[],
        )
        .0;

        debug!(
            "Special Transaction Generator: erc20 contract address: {:?}",
            erc20_address
        );

        DirectTransactionGenerator {
            accounts,
            address_by_index,
            erc20_address,
        }
    }

    pub fn generate_transactions(
        &mut self, block_size_limit: &mut usize, mut num_txs_simple: usize,
        mut num_txs_erc20: usize,
    ) -> Vec<Arc<SignedTransaction>>
    {
        let mut result = vec![];
        // Generate new address with 10% probability
        while num_txs_simple > 0 {
            let number_of_accounts = self.address_by_index.len();

            let sender_index: usize = random::<usize>() % number_of_accounts;
            let sender_address =
                self.address_by_index.get(sender_index).unwrap().clone();
            let sender_kp;
            let sender_balance;
            let sender_nonce;
            {
                let sender_info = self.accounts.get(&sender_address).unwrap();
                sender_kp = sender_info.0.clone();
                sender_balance = sender_info.1.balance;
                sender_nonce = sender_info.1.nonce;
            }

            let gas = U256::from(100_000u64);
            let gas_price = U256::from(1u64);
            let transaction_fee = U256::from(100_000u64);

            if sender_balance <= transaction_fee {
                self.accounts.remove(&sender_address);
                self.address_by_index.swap_remove(sender_index);
                continue;
            }

            let balance_to_transfer = U256::try_from(
                H512::random().into_uint() % U512::from(sender_balance),
            )
            .unwrap();

            let is_send_to_new_address = (number_of_accounts
                <= Self::MAX_TOTAL_ACCOUNTS)
                && ((number_of_accounts < 10)
                    || (rand::thread_rng().gen_range(0, 10) == 0));

            let receiver_address = match is_send_to_new_address {
                false => {
                    let index: usize = random::<usize>() % number_of_accounts;
                    self.address_by_index.get(index).unwrap().clone()
                }
                true => loop {
                    let kp =
                        Random.generate().expect("Fail to generate KeyPair.");
                    let address = public_to_address(kp.public());
                    if self.accounts.get(&address).is_none() {
                        self.accounts.insert(
                            address,
                            (
                                kp,
                                Account::new_empty_with_balance(
                                    &address,
                                    &0.into(), /* balance */
                                    &0.into(), /* nonce */
                                ),
                                0.into(),
                            ),
                        );
                        self.address_by_index.push(address.clone());

                        break address;
                    }
                },
            };

            let tx = Transaction {
                nonce: sender_nonce,
                gas_price,
                gas,
                value: balance_to_transfer,
                action: Action::Call(receiver_address),
                storage_limit: U256::MAX,
                data: vec![0u8; 128],
            };
            let signed_transaction = tx.sign(sender_kp.secret());
            let rlp_size = signed_transaction.transaction.rlp_bytes().len();
            if *block_size_limit <= rlp_size {
                break;
            }
            *block_size_limit -= rlp_size;

            self.accounts.get_mut(&sender_address).unwrap().1.balance -=
                balance_to_transfer;
            self.accounts.get_mut(&sender_address).unwrap().1.nonce += 1.into();
            self.accounts.get_mut(&receiver_address).unwrap().1.balance +=
                balance_to_transfer;

            result.push(Arc::new(signed_transaction));

            num_txs_simple -= 1;
        }

        while num_txs_erc20 > 0 {
            let number_of_accounts = self.address_by_index.len();

            let sender_index: usize = random::<usize>() % number_of_accounts;
            let sender_address =
                self.address_by_index.get(sender_index).unwrap().clone();
            let sender_kp;
            let sender_balance;
            let sender_erc20_balance;
            let sender_nonce;
            {
                let sender_info = self.accounts.get(&sender_address).unwrap();
                sender_kp = sender_info.0.clone();
                sender_balance = sender_info.1.balance;
                sender_erc20_balance = sender_info.2.clone();
                sender_nonce = sender_info.1.nonce;
            }

            let gas = U256::from(100_000u64);
            let gas_price = U256::from(1u64);
            let transaction_fee = U256::from(100_000u64);

            if sender_balance <= transaction_fee {
                self.accounts.remove(&sender_address);
                self.address_by_index.swap_remove(sender_index);
                continue;
            }

            let balance_to_transfer = if sender_erc20_balance == 0.into() {
                continue;
            } else {
                U256::try_from(
                    H512::random().into_uint()
                        % U512::from(sender_erc20_balance),
                )
                .unwrap()
            };

            let receiver_index = random::<usize>() % number_of_accounts;
            let receiver_address =
                self.address_by_index.get(receiver_index).unwrap().clone();

            if receiver_index == sender_index {
                continue;
            }

            // Calls transfer of ERC20 contract.
            let tx_data = Vec::from_hex(
                String::new()
                    + "a9059cbb000000000000000000000000"
                    + &receiver_address.to_hex()[2..]
                    + {
                        let h: H256 =
                            BigEndianHash::from_uint(&balance_to_transfer);
                        &h.to_hex()[2..]
                    },
            )
            .unwrap();

            let tx = Transaction {
                nonce: sender_nonce,
                gas_price,
                gas,
                value: 0.into(),
                action: Action::Call(self.erc20_address.clone()),
                storage_limit: U256::MAX,
                data: tx_data,
            };
            let signed_transaction = tx.sign(sender_kp.secret());
            let rlp_size = signed_transaction.transaction.rlp_bytes().len();
            if *block_size_limit <= rlp_size {
                break;
            }
            *block_size_limit -= rlp_size;

            self.accounts.get_mut(&sender_address).unwrap().2 -=
                balance_to_transfer;
            self.accounts.get_mut(&sender_address).unwrap().1.nonce += 1.into();
            self.accounts.get_mut(&receiver_address).unwrap().2 +=
                balance_to_transfer;

            result.push(Arc::new(signed_transaction));

            num_txs_erc20 -= 1;
        }

        result
    }
}
