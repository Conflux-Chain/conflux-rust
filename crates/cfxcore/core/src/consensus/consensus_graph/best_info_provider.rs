use super::ConsensusGraph;

pub use crate::consensus::{
    consensus_inner::{ConsensusGraphInner, ConsensusInnerConfig},
    consensus_trait::SharedConsensusGraph,
};
use crate::{
    block_data_manager::{
        BlockDataManager, BlockExecutionResultWithEpoch, DataVersionTuple,
    },
    consensus::{
        consensus_inner::{
            consensus_executor::ConsensusExecutionConfiguration, StateBlameInfo,
        },
        pos_handler::PosVerifier,
    },
    errors::{invalid_params, invalid_params_check, Result as CoreResult},
    pow::{PowComputer, ProofOfWorkConfig},
    statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool,
    verification::VerificationConfig,
    NodeType, Notifications,
};
use cfx_execute_helper::{
    estimation::{EstimateExt, EstimateRequest},
    exec_tracer::{
        recover_phantom_traces, ActionType, BlockExecTraces, LocalizedTrace,
        TraceFilter,
    },
    phantom_tx::build_bloom_and_recover_phantom,
};
use cfx_executor::{
    executive::ExecutionOutcome, spec::CommonParams, state::State,
};
use cfx_rpc_eth_types::EvmOverrides;
use geth_tracer::GethTraceWithHash;

use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use cfx_internal_common::ChainIdParams;
use cfx_parameters::{
    consensus::*,
    consensus_internal::REWARD_EPOCH_COUNT,
    rpc::{
        GAS_PRICE_BLOCK_SAMPLE_SIZE, GAS_PRICE_DEFAULT_VALUE,
        GAS_PRICE_TRANSACTION_SAMPLE_SIZE,
    },
};
use cfx_rpc_cfx_types::PhantomBlock;
use cfx_statedb::StateDb;
use cfx_storage::{
    state::StateTrait, state_manager::StateManagerTrait, StorageState,
};
use cfx_types::{AddressWithSpace, AllChainID, Bloom, Space, H256, U256};
use either::Either;
use itertools::Itertools;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Meter, MeterTimer,
};
use parking_lot::{Mutex, RwLock};
use primitives::{
    compute_block_number,
    epoch::BlockHashOrEpochNumber,
    filter::{FilterError, LogFilter},
    log_entry::LocalizedLogEntry,
    pos::PosBlockId,
    receipt::Receipt,
    Block, EpochId, EpochNumber, SignedTransaction, TransactionIndex,
    TransactionStatus,
};
use rayon::prelude::*;
use std::{
    cmp::{max, min},
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
    time::Duration,
};

lazy_static!{
    static ref BEST_EPOCH_NUMBER: Arc<dyn Gauge<usize>> = GaugeUsize::register_with_group("graph_statistic", "best_epoch_number");
}

#[derive(Default, Debug, DeriveMallocSizeOf)]
pub struct BestInformation {
    pub chain_id: AllChainID,
    pub best_block_hash: H256,
    pub best_epoch_number: u64,
    pub current_difficulty: U256,
    pub bounded_terminal_block_hashes: Vec<H256>,
    pub best_block_number: u64,
}

impl BestInformation {
    pub fn best_chain_id(&self) -> AllChainID { self.chain_id }
}

impl ConsensusGraph {
    
    pub fn best_info(&self) -> Arc<BestInformation> {
        self.best_info.read_recursive().clone()
    }

    pub fn best_epoch_number(&self) -> u64 {
        self.best_info.read_recursive().best_epoch_number
    }

    pub fn latest_checkpoint_epoch_number(&self) -> u64 {
        self.data_man
            .block_height_by_hash(
                &self.data_man.get_cur_consensus_era_genesis_hash(),
            )
            .expect("header for cur_era_genesis should exist")
    }

    pub fn latest_confirmed_epoch_number(&self) -> u64 {
        self.confirmation_meter.get_confirmed_epoch_num()
    }

    pub fn latest_finalized_epoch_number(&self) -> u64 {
        self.inner
            .read_recursive()
            .latest_epoch_confirmed_by_pos()
            .1
    }

    pub fn best_chain_id(&self) -> AllChainID {
        self.best_info.read_recursive().best_chain_id()
    }

    pub fn best_block_hash(&self) -> H256 {
        self.best_info.read_recursive().best_block_hash
    }
    

       /// This function is called after a new block appended to the
    /// ConsensusGraph. Because BestInformation is often queried outside. We
    /// store a version of best_info outside the inner to prevent keep
    /// getting inner locks.
    /// If `ready_for_mining` is `false`, the terminal information will not be
    /// needed, so we do not compute bounded terminals in this case.
    pub(super) fn update_best_info(&self, ready_for_mining: bool) {
        let mut inner = self.inner.write();
        let mut best_info = self.best_info.write();

        let bounded_terminal_block_hashes = if ready_for_mining {
            inner.bounded_terminal_block_hashes(self.config.referee_bound)
        } else {
            // `bounded_terminal` is only needed for mining and serve syncing.
            // As the computation cost is high, we do not compute it when we are
            // catching up because we cannot mine blocks in
            // catching-up phases. Use `best_block_hash` to
            // represent terminals here to remain consistent.
            vec![inner.best_block_hash()]
        };
        let best_epoch_number = inner.best_epoch_number();
        BEST_EPOCH_NUMBER.update(best_epoch_number as usize);
        *best_info = Arc::new(BestInformation {
            chain_id: self
                .config
                .chain_id
                .read()
                .get_chain_id(best_epoch_number),
            best_block_hash: inner.best_block_hash(),
            best_block_number: inner.best_block_number(),
            best_epoch_number,
            current_difficulty: inner.current_difficulty,
            bounded_terminal_block_hashes,
        });
        debug!("update_best_info to {:?}", best_info);
    }
}