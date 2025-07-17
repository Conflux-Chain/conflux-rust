pub(super) mod best_info_provider;
pub(super) mod mining_api;
pub(super) mod onchain_blocks_provider;
pub(super) mod rpc_api;
pub(super) mod sync_graph_api;

use self::best_info_provider::BestInformation;

use super::{
    consensus_inner::{
        confirmation_meter::ConfirmationMeter,
        consensus_executor::ConsensusExecutor,
        consensus_new_block_handler::ConsensusNewBlockHandler,
    },
    pivot_hint::PivotHint,
};
pub use crate::consensus::consensus_inner::ConsensusGraphInner;
use crate::{
    block_data_manager::BlockDataManager,
    consensus::{
        consensus_inner::consensus_executor::ConsensusExecutionConfiguration,
        pos_handler::PosVerifier,
    },
    pow::{PowComputer, ProofOfWorkConfig},
    statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool,
    verification::VerificationConfig,
    NodeType, Notifications,
};
pub use onchain_blocks_provider::EPOCH_NUMBER_TOO_LARGE_ERR_MESSAGE;

use cfx_executor::spec::CommonParams;

use super::config::ConsensusConfig;

use cfx_types::H256;

use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};

use parking_lot::{Mutex, RwLock};
use primitives::EpochId;

use std::sync::{atomic::AtomicBool, Arc};

/// ConsensusGraph is a layer on top of SynchronizationGraph. A SyncGraph
/// collect all blocks that the client has received so far, but a block can only
/// be delivered to the ConsensusGraph if 1) the whole block content is
/// available and 2) all of its past blocks are also in the ConsensusGraph.
///
/// ConsensusGraph maintains the TreeGraph structure of the client and
/// implements *Timer Chain GHAST*/*Conflux* algorithm to determine the block
/// total order. It dispatches transactions in epochs to ConsensusExecutor to
/// process. To avoid executing too many execution reroll caused by transaction
/// order oscillation. It defers the transaction execution for a few epochs.
///
/// When recovery from database, ConsensusGraph requires that 1) the data
/// manager is in a consistent state, 2) the data manager stores the correct era
/// genesis and era stable hash, and 3) the data manager contains correct *block
/// status* for all blocks before era stable block (more restrictively speaking,
/// whose past sets do not contain the stable block).
pub struct ConsensusGraph {
    pub inner: Arc<RwLock<ConsensusGraphInner>>,
    pub txpool: SharedTransactionPool,
    pub data_man: Arc<BlockDataManager>,
    executor: Arc<ConsensusExecutor>,
    statistics: SharedStatistics,
    pub new_block_handler: ConsensusNewBlockHandler,
    pub confirmation_meter: ConfirmationMeter,
    /// Make sure that it is only modified when holding inner lock to prevent
    /// any inconsistency
    best_info: RwLock<Arc<BestInformation>>,
    /// Set to `true` when we enter NormalPhase
    pub ready_for_mining: AtomicBool,

    /// The epoch id of the remotely synchronized state.
    /// This is always `None` for archive nodes.
    pub synced_epoch_id: Mutex<Option<EpochId>>,
    pub config: ConsensusConfig,
    pub params: CommonParams,
}

impl MallocSizeOf for ConsensusGraph {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let best_info_size = self.best_info.read().size_of(ops);
        self.inner.read().size_of(ops)
            + self.txpool.size_of(ops)
            + self.data_man.size_of(ops)
            + best_info_size
    }
}

impl ConsensusGraph {
    /// Build the ConsensusGraph with a specific era genesis block and various
    /// other components. The execution will be skipped if bench_mode sets
    /// to true.
    pub fn with_era_genesis(
        conf: ConsensusConfig, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig, pow: Arc<PowComputer>,
        era_genesis_block_hash: &H256, era_stable_block_hash: &H256,
        notifications: Arc<Notifications>,
        execution_conf: ConsensusExecutionConfiguration,
        verification_config: VerificationConfig, node_type: NodeType,
        pos_verifier: Arc<PosVerifier>, pivot_hint: Option<Arc<PivotHint>>,
        params: CommonParams,
    ) -> Self {
        let inner =
            Arc::new(RwLock::new(ConsensusGraphInner::with_era_genesis(
                pow_config,
                pow.clone(),
                pos_verifier.clone(),
                data_man.clone(),
                conf.inner_conf.clone(),
                era_genesis_block_hash,
                era_stable_block_hash,
            )));
        let executor = ConsensusExecutor::start(
            txpool.clone(),
            data_man.clone(),
            inner.clone(),
            execution_conf,
            verification_config,
            conf.bench_mode,
            pos_verifier.clone(),
        );
        let confirmation_meter = ConfirmationMeter::new();

        let graph = ConsensusGraph {
            inner,
            txpool: txpool.clone(),
            data_man: data_man.clone(),
            executor: executor.clone(),
            statistics: statistics.clone(),
            new_block_handler: ConsensusNewBlockHandler::new(
                conf.clone(),
                txpool,
                data_man,
                executor,
                statistics,
                notifications,
                node_type,
                pos_verifier,
                pivot_hint,
            ),
            confirmation_meter,
            best_info: RwLock::new(Arc::new(Default::default())),
            ready_for_mining: AtomicBool::new(false),
            synced_epoch_id: Default::default(),
            config: conf,
            params,
        };
        graph.update_best_info(false /* ready_for_mining */);
        graph
            .txpool
            .notify_new_best_info(graph.best_info.read_recursive().clone())
            // FIXME: propogate error.
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        graph
    }

    /// Build the ConsensusGraph with the initial (checkpointed) genesis block
    /// in the data manager and various other components. The execution will
    /// be skipped if bench_mode sets to true.
    pub fn new(
        conf: ConsensusConfig, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig, pow: Arc<PowComputer>,
        notifications: Arc<Notifications>,
        execution_conf: ConsensusExecutionConfiguration,
        verification_conf: VerificationConfig, node_type: NodeType,
        pos_verifier: Arc<PosVerifier>, pivot_hint: Option<Arc<PivotHint>>,
        params: CommonParams,
    ) -> Self {
        let genesis_hash = data_man.get_cur_consensus_era_genesis_hash();
        let stable_hash = data_man.get_cur_consensus_era_stable_hash();
        ConsensusGraph::with_era_genesis(
            conf,
            txpool,
            statistics,
            data_man,
            pow_config,
            pow,
            &genesis_hash,
            &stable_hash,
            notifications,
            execution_conf,
            verification_conf,
            node_type,
            pos_verifier,
            pivot_hint,
            params,
        )
    }

    /// Get the number of processed blocks (i.e., the number of calls to
    /// on_new_block()
    #[cfg(feature = "consensus_bench")]
    pub fn get_processed_block_count(&self) -> usize {
        self.statistics.get_consensus_graph_processed_block_count()
    }

    pub fn config(&self) -> &ConsensusConfig { &self.config }

    pub fn data_manager(&self) -> &Arc<BlockDataManager> { &self.data_man }

    pub fn tx_pool(&self) -> &SharedTransactionPool { &self.txpool }
}

impl Drop for ConsensusGraph {
    fn drop(&mut self) { self.executor.stop(); }
}
