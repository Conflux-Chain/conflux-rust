// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Recursion limit raised for error_chain
#![recursion_limit = "256"]

extern crate cfx_bytes as bytes;
#[macro_use]
extern crate cfx_internal_common;
extern crate cfxkey as keylib;
extern crate keccak_hash as hash;
#[macro_use]
extern crate log;
#[macro_use]
extern crate error_chain;
extern crate db as ext_db;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate static_assertions;

#[macro_use]
pub mod message;

pub mod block_data_manager;
mod builtin;
pub mod cache_config;
pub mod cache_manager;
pub mod channel;
pub mod client;
pub mod consensus;
pub mod db;
pub mod error;
mod evm;
pub mod executive;
pub mod light_protocol;
pub mod machine;
pub mod node_type;
pub mod pow;
pub mod rpc_errors;
pub mod spec;
pub mod state;
pub mod state_exposer;
pub mod statistics;
pub mod sync;
pub mod trace;
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
    node_type::NodeType,
    sync::{
        SharedSynchronizationGraph, SharedSynchronizationService,
        SynchronizationGraph, SynchronizationService,
    },
    transaction_pool::{SharedTransactionPool, TransactionPool},
    unique_id::UniqueId,
};
pub use cfx_parameters::{
    block as block_parameters, consensus as consensus_parameters,
    consensus_internal as consensus_internal_parameters,
    sync as sync_parameters, WORKER_COMPUTATION_PARALLELISM,
};
pub use network::PeerInfo;

pub trait Stopable {
    fn stop(&self);
}
