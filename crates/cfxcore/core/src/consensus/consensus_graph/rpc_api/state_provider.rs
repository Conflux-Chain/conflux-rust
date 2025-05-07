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


use super::super::ConsensusGraph;

impl ConsensusGraph {
    pub fn get_storage_state_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StorageState> {
        invalid_params_check(
            rpc_param_name,
            self.validate_stated_epoch(&epoch_number),
        )?;
        let height = invalid_params_check(
            rpc_param_name,
            self.get_height_from_epoch_number(epoch_number),
        )?;
        let hash =
            self.inner.read().get_pivot_hash_from_epoch_number(height)?;
        self.get_storage_state_by_height_and_hash(height, &hash)
    }

    pub fn get_eth_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StateDb> {
        self.get_state_db_by_epoch_number_with_space(
            epoch_number,
            rpc_param_name,
            Some(Space::Ethereum),
        )
    }

    pub fn get_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StateDb> {
        self.get_state_db_by_epoch_number_with_space(
            epoch_number,
            rpc_param_name,
            None,
        )
    }

    fn get_state_db_by_epoch_number_with_space(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
        space: Option<Space>,
    ) -> CoreResult<StateDb> {
        invalid_params_check(
            rpc_param_name,
            self.validate_stated_epoch(&epoch_number),
        )?;
        let height = invalid_params_check(
            rpc_param_name,
            self.get_height_from_epoch_number(epoch_number),
        )?;
        let hash =
            self.inner.read().get_pivot_hash_from_epoch_number(height)?;
        Ok(StateDb::new(
            self.get_state_by_height_and_hash(height, &hash, space)?,
        ))
    }

    fn get_storage_state_by_height_and_hash(
        &self, height: u64, hash: &H256,
    ) -> CoreResult<StorageState> {
        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();
        if !state_availability_boundary.check_availability(height, &hash) {
            debug!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            );
            bail!(format!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            ));
        }
        let maybe_state_readonly_index =
            self.data_man.get_state_readonly_index(&hash).into();
        let maybe_state = match maybe_state_readonly_index {
            Some(state_readonly_index) => self
                .data_man
                .storage_manager
                .get_state_no_commit_inner(
                    state_readonly_index,
                    /* try_open = */ true,
                    true,
                )
                .map_err(|e| format!("Error to get state, err={:?}", e))?,
            None => None,
        };

        let state = match maybe_state {
            Some(state) => state,
            None => {
                bail!(format!(
                    "State for epoch (number={:?} hash={:?}) does not exist",
                    height, hash
                ));
            }
        };

        Ok(state)
    }

    fn get_state_by_height_and_hash(
        &self, height: u64, hash: &H256, space: Option<Space>,
    ) -> CoreResult<Box<dyn StateTrait>> {
        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();
        if !state_availability_boundary
            .check_read_availability(height, &hash, space)
        {
            debug!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            );
            bail!(format!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            ));
        }
        let maybe_state_readonly_index =
            self.data_man.get_state_readonly_index(&hash).into();
        let maybe_state = match maybe_state_readonly_index {
            Some(state_readonly_index) => self
                .data_man
                .storage_manager
                .get_state_no_commit(
                    state_readonly_index,
                    /* try_open = */ true,
                    space,
                )
                .map_err(|e| format!("Error to get state, err={:?}", e))?,
            None => None,
        };

        let state = match maybe_state {
            Some(state) => state,
            None => {
                bail!(format!(
                    "State for epoch (number={:?} hash={:?}) does not exist",
                    height, hash
                ));
            }
        };

        Ok(state)
    }
}