use super::super::ConsensusGraph;

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


impl ConsensusGraph {
    pub fn get_block_execution_info(
        &self, block_hash: &H256,
    ) -> Option<(BlockExecutionResultWithEpoch, Option<H256>)> {
        let results_with_epoch = self
            .inner
            .read_recursive()
            .block_execution_results_by_hash(block_hash, true)?;

        let pivot_hash = results_with_epoch.0;

        let maybe_state_root = match self.executor.wait_for_result(pivot_hash) {
            Ok(execution_commitment) => {
                // We already has transaction address with epoch_hash executed,
                // so we can always get the state_root with
                // `wait_for_result`
                Some(
                    execution_commitment
                        .state_root_with_aux_info
                        .aux_info
                        .state_root_hash,
                )
            }
            Err(msg) => {
                warn!("get_transaction_receipt_and_block_info() gets the following error from ConsensusExecutor: {}", msg);
                None
            }
        };

        Some((results_with_epoch, maybe_state_root))
    }


    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch: EpochNumber,
        request: EstimateRequest, evm_overrides: EvmOverrides,
    ) -> CoreResult<(ExecutionOutcome, EstimateExt)> {
        // only allow to call against stated epoch
        self.validate_stated_epoch(&epoch)?;
        let (epoch_id, epoch_size) = if let Ok(v) =
            self.get_block_hashes_by_epoch(epoch)
        {
            (v.last().expect("pivot block always exist").clone(), v.len())
        } else {
            bail!("cannot get block hashes in the specified epoch, maybe it does not exist?");
        };
        self.executor.call_virtual(
            tx,
            &epoch_id,
            epoch_size,
            request,
            evm_overrides,
        )
    }
}