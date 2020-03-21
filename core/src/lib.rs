// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Recursion limit raised for error_chain
#![recursion_limit = "512"]
#![allow(deprecated)]

extern crate cfx_bytes as bytes;
extern crate cfxkey as keylib;
extern crate core;
extern crate io;
extern crate keccak_hash as hash;
#[macro_use]
extern crate log;
extern crate network;
extern crate parking_lot;
extern crate primitives;
extern crate rand;
extern crate rlp;
extern crate secret_store;
#[macro_use]
extern crate error_chain;
extern crate db as ext_db;
extern crate kvdb;
extern crate slab;
#[macro_use]
extern crate lazy_static;
extern crate bit_set;
extern crate bn;
extern crate byteorder;
extern crate libra_canonical_serialization as lcs;
extern crate memory_cache;
extern crate num;
extern crate parity_crypto;
#[macro_use]
extern crate prometheus;
extern crate futures;
#[cfg(test)]
extern crate rustc_hex;
extern crate schemadb;
extern crate serde;
extern crate serde_derive;
extern crate unexpected;

pub mod block_data_manager;
mod builtin;
pub mod cache_config;
pub mod cache_manager;
pub mod consensus;
pub mod db;
pub mod error;
mod evm;
pub mod executive;
pub mod genesis;
mod parameters;
#[macro_use]
pub mod message;
pub mod alliance_tree_graph;
pub mod channel;
pub mod client;
pub mod light_protocol;
pub mod machine;
pub mod miner;
pub mod pow;
pub mod state;
pub mod state_exposer;
pub mod statedb;
pub mod statistics;
pub mod storage;
pub mod sync;
pub mod transaction_pool;
pub mod unique_id;
pub mod verification;
pub mod vm;
pub mod vm_factory;

pub mod test_helpers;

pub use crate::{
    block_data_manager::BlockDataManager,
    channel::Notifications,
    consensus::{
        BestInformation, ConsensusGraph, ConsensusGraphTrait,
        SharedConsensusGraph,
    },
    light_protocol::{
        Provider as LightProvider, QueryService as LightQueryService,
    },
    sync::{
        SharedSynchronizationGraph, SharedSynchronizationService,
        SynchronizationGraph, SynchronizationService,
    },
    transaction_pool::{SharedTransactionPool, TransactionPool},
    unique_id::UniqueId,
};
pub use network::PeerInfo;
pub use parameters::{
    block as block_parameters, consensus as consensus_parameters,
    consensus_internal as consensus_internal_parameters,
    sync as sync_parameters, WORKER_COMPUTATION_PARALLELISM,
};

/// TODO Disable/enable at compilation time.
/// This module can trigger random process crashes during testing.
/// This is only used to insert crashes before db modifications.
pub mod test_context {
    use parking_lot::Mutex;
    use rand::{thread_rng, Rng};
    lazy_static! {
        /// The process exit code set for random crash.
        pub static ref CRASH_EXIT_CODE: Mutex<i32> = Mutex::new(100);
        /// The probability to trigger a random crash.
        /// Set to `None` to disable random crash.
        pub static ref CRASH_EXIT_PROBABILITY: Mutex<Option<f64>> =
            Mutex::new(None);
    }

    /// Randomly crash with the probability and exit code already set.
    pub fn random_crash_if_enabled(exit_str: &str) {
        if let Some(p) = *CRASH_EXIT_PROBABILITY.lock() {
            if thread_rng().gen_bool(p) {
                info!("exit before {}", exit_str);
                std::process::exit(*CRASH_EXIT_CODE.lock());
            }
        }
    }
}

pub trait Stopable {
    fn stop(&self);
}
