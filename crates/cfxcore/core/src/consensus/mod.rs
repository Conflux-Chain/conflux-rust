// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod anticone_cache;
mod config;
mod consensus_graph;
pub mod consensus_inner;
pub mod debug_recompute;
mod pastset_cache;
pub mod pivot_hint;
pub mod pos_handler;
mod statistics;

pub use crate::consensus::consensus_inner::{
    ConsensusGraphInner, ConsensusInnerConfig,
};

pub use config::ConsensusConfig;
pub use consensus_graph::{
    best_info_provider::BestInformation,
    rpc_api::transaction_provider::{
        MaybeExecutedTxExtraInfo, TransactionInfo,
    },
    ConsensusGraph,
};
pub use statistics::ConsensusGraphStatistics;

use std::sync::Arc;
pub type SharedConsensusGraph = Arc<ConsensusGraph>;
