// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate cfx_bytes as bytes;
extern crate core;
extern crate keylib;
extern crate network;
extern crate parking_lot;
extern crate primitives;
extern crate rand;
extern crate secret_store;
#[macro_use]
extern crate log;

use crate::bytes::Bytes;
use cfx_types::{Address, H512, U256, U512};
use cfxcore::{
    state::State,
    statedb::StateDb,
    storage::{StorageManager, StorageManagerTrait},
    SharedConsensusGraph, SharedTransactionPool,
};
use keylib::{public_to_address, Generator, KeyPair, Random};
use network::Error;
use parking_lot::RwLock;
use primitives::{transaction::Action, SignedTransaction, Transaction};
use rand::prelude::*;
use secret_store::{SecretStore, SharedSecretStore};
use std::{collections::HashMap, sync::Arc, thread, time};

pub mod propagate;

#[allow(unused)]
enum TransGenState {
    Start,
    Stop,
}

pub struct TransactionGeneratorConfig {
    pub generate_tx: bool,
    pub period: time::Duration,
}

impl TransactionGeneratorConfig {
    pub fn new(generate_tx: bool, period_ms: u64) -> Self {
        TransactionGeneratorConfig {
            generate_tx,
            period: time::Duration::from_millis(period_ms),
        }
    }
}

pub struct TransactionGenerator {
    pub consensus: SharedConsensusGraph,
    pub storage_manager: Arc<StorageManager>,
    txpool: SharedTransactionPool,
    secret_store: SharedSecretStore,
    state: RwLock<TransGenState>,
    key_pair: Option<KeyPair>,
}

pub type SharedTransactionGenerator = Arc<TransactionGenerator>;

impl TransactionGenerator {
    pub fn new(
        consensus: SharedConsensusGraph, storage_manager: Arc<StorageManager>,
        txpool: SharedTransactionPool, secret_store: SharedSecretStore,
        key_pair: Option<KeyPair>,
    ) -> Self
    {
        TransactionGenerator {
            consensus,
            storage_manager,
            txpool,
            secret_store,
            state: RwLock::new(TransGenState::Start),
            key_pair,
        }
    }

    pub fn get_best_state(&self) -> State {
        State::new(
            StateDb::new(
                self.storage_manager
                    .get_state_at(self.consensus.best_state_block_hash())
                    .unwrap(),
            ),
            0.into(),
            Default::default(),
        )
    }

    pub fn generate_transaction(&self) -> SignedTransaction {
        // Generate new address with 10% probability
        let is_send_to_new_address = (rand::thread_rng().gen_range(0, 10) == 0)
            || (self.secret_store.count() < 10);
        let receiver_address = match is_send_to_new_address {
            false => {
                let account_count = self.secret_store.count();
                let index: usize = random::<usize>() % account_count;
                let kp = self.secret_store.get_keypair(index);
                public_to_address(kp.public())
            }
            true => {
                let kp = Random.generate().expect("Fail to generate KeyPair.");
                self.secret_store.insert(kp.clone());
                public_to_address(kp.public())
            }
        };

        let account_count = self.secret_store.count();
        let sender_index: usize = random::<usize>() % account_count;
        let sender_kp = self.secret_store.get_keypair(sender_index);
        let sender_address = public_to_address(sender_kp.public());

        let state = self.get_best_state();

        debug!(
            "account_count:{} sender_addr:{:?} epoch_id:{:?}",
            account_count,
            sender_address,
            self.consensus.best_state_block_hash()
        );
        let sender_balance = state.balance(&sender_address).unwrap_or(0.into());

        let sender_nonce = state.nonce(&sender_address).unwrap_or(0.into());

        let mut balance_to_transfer: U256 = 0.into();
        if sender_balance > 0.into() {
            balance_to_transfer = U256::from(
                U512::from(H512::random()) % U512::from(sender_balance),
            );
        }

        let tx = Transaction {
            nonce: sender_nonce,
            gas_price: U256::from(100u64),
            gas: U256::from(1u64),
            value: balance_to_transfer,
            action: Action::Call(receiver_address),
            data: Bytes::new(),
        };
        let r = tx.sign(sender_kp.secret());
        r
    }

    pub fn generate_transactions(
        txgen: Arc<TransactionGenerator>, tx_config: TransactionGeneratorConfig,
    ) -> Result<(), Error> {
        let mut nonce_map: HashMap<Address, U256> = HashMap::new();
        let mut balance_map: HashMap<Address, U256> = HashMap::new();

        let key_pair = txgen.key_pair.clone().expect("should exist");
        let secret_store = SecretStore::new();
        //        let mut balance_map = HashMap::new();
        //        balance_map
        //            .insert(public_to_address(key_pair.public()),
        // U256::from(10000000));
        debug!(
            "tx_gen address={:?} pub_key={:?}",
            public_to_address(key_pair.public()),
            key_pair.public()
        );
        debug!("{:?} {:?}", tx_config.generate_tx, tx_config.period);
        secret_store.insert(key_pair);
        let mut tx_n = 0;
        loop {
            match *txgen.state.read() {
                TransGenState::Stop => return Ok(()),
                _ => {}
            }

            let state = State::new(
                StateDb::new(
                    txgen
                        .storage_manager
                        .get_state_at(txgen.consensus.best_state_block_hash())
                        .unwrap(),
                ),
                0.into(),
                Default::default(),
            );

            // Randomly select sender and receiver.
            // Sender must exist in the account list.
            // Receiver can be not in the account list which
            // leads to generate a new account
            let account_count = secret_store.count();
            let mut sender_index: usize = random();
            sender_index %= account_count;
            let sender_kp = secret_store.get_keypair(sender_index);

            // Randomly generate the to-be-transferred value
            // based on the balance of sender
            let sender_address = public_to_address(sender_kp.public());
            let sender_balance = state.balance(&sender_address).ok();

            trace!(
                "choose sender addr={:?} balance={:?}",
                sender_address,
                sender_balance
            );
            if sender_balance.is_none()
                || sender_balance.clone().unwrap() == 0.into()
            {
                thread::sleep(tx_config.period);
                continue;
            }
            let sender_balance = balance_map
                .entry(sender_address)
                .or_insert(sender_balance.unwrap());
            if *sender_balance < 42000.into() {
                secret_store.remove_keypair(sender_index);
                if secret_store.count() == 0 {
                    break;
                }
                continue;
            }

            let mut balance_to_transfer = U256::from(0);
            let mut receiver_kp: KeyPair;
            let mut receiver_index: usize = random();
            receiver_index %= account_count;
            if sender_index == receiver_index && secret_store.count() < 20000 {
                balance_to_transfer = *sender_balance / 2;
                // Create a new receiver account
                loop {
                    receiver_kp = Random.generate()?;
                    if secret_store.insert(receiver_kp.clone()) {
                        break;
                    }
                }
            } else {
                receiver_kp = secret_store.get_keypair(receiver_index);
            }
            *sender_balance -= balance_to_transfer + 21000;
            // Generate nonce for the transaction
            let sender_state_nonce = state.nonce(&sender_address).unwrap();
            let entry = nonce_map
                .entry(sender_address)
                .or_insert(sender_state_nonce);
            if sender_state_nonce > *entry {
                *entry = sender_state_nonce;
            }
            let sender_nonce = *entry;
            *entry += U256::one();

            let receiver_address = public_to_address(receiver_kp.public());
            trace!(
                "receiver={:?} value={:?} nonce={:?}",
                receiver_address,
                balance_to_transfer,
                sender_nonce
            );
            *balance_map.entry(receiver_address).or_insert(0.into()) +=
                balance_to_transfer;
            // Generate the transaction, sign it, and push into the transaction
            // pool
            let tx = Transaction {
                nonce: sender_nonce,
                gas_price: U256::from(1u64),
                gas: U256::from(21000u64),
                value: balance_to_transfer,
                action: Action::Call(receiver_address),
                data: Bytes::new(),
            };

            let signed_tx = tx.sign(sender_kp.secret());
            //            txgen.txpool.add_pending(signed_tx.clone());
            let mut tx_to_insert = Vec::new();
            tx_to_insert.push(signed_tx.transaction);
            txgen.txpool.insert_new_transactions(
                txgen.consensus.best_state_block_hash(),
                tx_to_insert,
            );
            tx_n += 1;
            if tx_n % 100 == 0 {
                info!("Generated {} transactions", tx_n);
            }
            thread::sleep(tx_config.period);
        }
        Ok(())
    }
}
