// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
#![allow(unused)]

use crate::{
    block_data_manager::BlockDataManager,
    consensus::{BestInformation},
    errors::Result as CoreResult,
    statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool,
    ConsensusGraph,
};
use cfx_statedb::StateDb;
use cfx_storage::StorageState;
use cfx_types::{AllChainID, H256, U256};
use primitives::{EpochId, EpochNumber, SignedTransaction};
use std::{any::Any, collections::HashSet, sync::Arc};

pub type SharedConsensusGraph = Arc<ConsensusGraph>;
