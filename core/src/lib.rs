// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Recursion limit raised for error_chain
#![recursion_limit = "128"]
#![allow(deprecated)]

extern crate cfx_bytes as bytes;
extern crate core;
extern crate elastic_array;
extern crate ethkey as keylib;
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
extern crate memory_cache;
extern crate num;
extern crate parity_crypto;
extern crate serde_derive;

#[cfg(test)]
extern crate rustc_hex;
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
pub mod verification;
pub mod vm;
pub mod vm_factory;

pub mod test_helpers;

pub use crate::{
    block_data_manager::BlockDataManager,
    consensus::{BestInformation, ConsensusGraph, SharedConsensusGraph},
    light_protocol::{
        Provider as LightProvider, QueryService as LightQueryService,
    },
    sync::{
        SharedSynchronizationGraph, SharedSynchronizationService,
        SynchronizationGraph, SynchronizationService,
    },
    transaction_pool::{SharedTransactionPool, TransactionPool},
};
pub use network::PeerInfo;
pub use parameters::{
    block as block_parameters, consensus as consensus_parameters,
    WORKER_COMPUTATION_PARALLELISM,
};
