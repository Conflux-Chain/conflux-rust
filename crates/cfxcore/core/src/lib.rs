// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[macro_use]
extern crate log;
#[macro_use]
extern crate cfx_util_macros;
#[macro_use]
extern crate lazy_static;

use cfxkey as keylib;
use keccak_hash as hash;

#[macro_use]
pub mod message;

pub mod block_data_manager;
pub mod cache_config;
pub mod cache_manager;
pub mod channel;
pub mod client;
pub mod consensus;
mod core_error;
pub mod db;
pub mod errors;
pub mod genesis_block;
pub mod light_protocol;
pub mod node_type;
pub mod pos;
pub mod pow;
pub mod state_exposer;
pub mod statistics;
pub mod sync;
pub mod transaction_pool;
pub mod unique_id;
pub mod verification;

pub use crate::{
    block_data_manager::BlockDataManager,
    channel::Notifications,
    consensus::{
        BestInformation, ConsensusGraph, ConsensusGraphTrait,
        SharedConsensusGraph,
    },
    light_protocol::{
        Handler as LightHandler, Provider as LightProvider,
        QueryService as LightQueryService,
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
