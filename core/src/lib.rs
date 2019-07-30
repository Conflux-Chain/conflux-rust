// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(deprecated)]
extern crate cfx_bytes as bytes;
extern crate core;
extern crate elastic_array;
extern crate io;
extern crate keccak_hash as hash;
extern crate keylib;
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
extern crate heapsize;
extern crate memory_cache;
extern crate num;
extern crate parity_crypto;

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
#[macro_use]
pub mod message;
pub mod light_protocol;
pub mod machine;
pub mod pow;
pub(crate) mod snapshot;
pub mod state;
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
    consensus::{BestInformation, ConsensusGraph, SharedConsensusGraph},
    light_protocol::QueryService,
    sync::{
        SharedSynchronizationGraph, SharedSynchronizationService,
        SynchronizationGraph, SynchronizationService,
    },
    transaction_pool::{SharedTransactionPool, TransactionPool},
    verification::REFEREE_BOUND,
};
pub use network::PeerInfo;
