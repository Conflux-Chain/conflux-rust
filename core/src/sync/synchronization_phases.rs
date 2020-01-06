// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::StateAvailabilityBoundary,
    consensus::ConsensusGraphInner,
    parameters::{consensus::NULL, sync::CATCH_UP_EPOCH_LAG_THRESHOLD},
    sync::{
        message::DynamicCapability,
        state::{SnapshotChunkSync, Status},
        synchronization_protocol_handler::SynchronizationProtocolHandler,
        synchronization_state::SynchronizationState,
        SharedSynchronizationGraph, SynchronizationGraphInner,
    },
};
use network::NetworkContext;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    },
    thread, time,
};

///
/// Archive node goes through the following phases:
///     CatchUpRecoverBlockFromDB --> CatchUpSyncBlock --> Normal
///
/// Full node goes through the following phases:
///     CatchUpRecoverBlockHeaderFromDB --> CatchUpSyncBlockHeader -->
///     CatchUpCheckpoint --> CatchUpRecoverBlockFromDB -->
///     CatchUpSyncBlock --> Normal

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum SyncPhaseType {
    CatchUpRecoverBlockHeaderFromDB = 0,
    CatchUpSyncBlockHeader = 1,
    CatchUpCheckpoint = 2,
    CatchUpRecoverBlockFromDB = 3,
    CatchUpSyncBlock = 4,
    Normal = 5,
}

pub trait SynchronizationPhaseTrait: Send + Sync {
    fn name(&self) -> &'static str;
    fn phase_type(&self) -> SyncPhaseType;
    fn next(
        &self, _io: &dyn NetworkContext,
        _sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType;
    fn start(
        &self, _io: &dyn NetworkContext,
        _sync_handler: &SynchronizationProtocolHandler,
    );
}

pub struct SynchronizationPhaseManagerInner {
    initialized: bool,
    current_phase: SyncPhaseType,
    phases: HashMap<SyncPhaseType, Arc<dyn SynchronizationPhaseTrait>>,
}

impl SynchronizationPhaseManagerInner {
    pub fn new(initial_phase_type: SyncPhaseType) -> Self {
        SynchronizationPhaseManagerInner {
            initialized: false,
            current_phase: initial_phase_type,
            phases: HashMap::new(),
        }
    }

    pub fn register_phase(
        &mut self, phase: Arc<dyn SynchronizationPhaseTrait>,
    ) {
        self.phases.insert(phase.phase_type(), phase);
    }

    pub fn get_phase(
        &self, phase_type: SyncPhaseType,
    ) -> Arc<dyn SynchronizationPhaseTrait> {
        self.phases.get(&phase_type).unwrap().clone()
    }

    pub fn get_current_phase(&self) -> Arc<dyn SynchronizationPhaseTrait> {
        self.get_phase(self.current_phase)
    }

    pub fn change_phase_to(&mut self, phase_type: SyncPhaseType) {
        self.current_phase = phase_type;
    }

    pub fn try_initialize(&mut self) -> bool {
        let initialized = self.initialized;
        if !self.initialized {
            self.initialized = true;
        }

        initialized
    }
}

pub struct SynchronizationPhaseManager {
    inner: RwLock<SynchronizationPhaseManagerInner>,
}

impl SynchronizationPhaseManager {
    pub fn new(
        initial_phase_type: SyncPhaseType,
        sync_state: Arc<SynchronizationState>,
        sync_graph: SharedSynchronizationGraph,
        state_sync: Arc<SnapshotChunkSync>,
    ) -> Self
    {
        let sync_manager = SynchronizationPhaseManager {
            inner: RwLock::new(SynchronizationPhaseManagerInner::new(
                initial_phase_type,
            )),
        };

        sync_manager.register_phase(Arc::new(
            CatchUpRecoverBlockHeaderFromDbPhase::new(sync_graph.clone()),
        ));
        sync_manager.register_phase(Arc::new(
            CatchUpSyncBlockHeaderPhase::new(
                sync_state.clone(),
                sync_graph.clone(),
            ),
        ));
        sync_manager
            .register_phase(Arc::new(CatchUpCheckpointPhase::new(state_sync)));
        sync_manager.register_phase(Arc::new(
            CatchUpRecoverBlockFromDbPhase::new(sync_graph.clone()),
        ));
        sync_manager.register_phase(Arc::new(CatchUpSyncBlockPhase::new(
            sync_state.clone(),
            sync_graph.clone(),
        )));
        sync_manager.register_phase(Arc::new(NormalSyncPhase::new()));

        sync_manager
    }

    pub fn register_phase(&self, phase: Arc<dyn SynchronizationPhaseTrait>) {
        self.inner.write().register_phase(phase);
    }

    pub fn get_phase(
        &self, phase_type: SyncPhaseType,
    ) -> Arc<dyn SynchronizationPhaseTrait> {
        self.inner.read().get_phase(phase_type)
    }

    pub fn get_current_phase(&self) -> Arc<dyn SynchronizationPhaseTrait> {
        self.inner.read().get_current_phase()
    }

    pub fn change_phase_to(
        &self, phase_type: SyncPhaseType, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        self.inner.write().change_phase_to(phase_type);
        let current_phase = self.get_current_phase();
        current_phase.start(io, sync_handler);
    }

    pub fn try_initialize(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        if !self.inner.write().try_initialize() {
            // if not initialized
            let current_phase = self.get_current_phase();
            current_phase.start(io, sync_handler);
        }
    }
}

pub struct CatchUpRecoverBlockHeaderFromDbPhase {
    pub graph: SharedSynchronizationGraph,
    pub recovered: Arc<AtomicBool>,
}

impl CatchUpRecoverBlockHeaderFromDbPhase {
    pub fn new(graph: SharedSynchronizationGraph) -> Self {
        CatchUpRecoverBlockHeaderFromDbPhase {
            graph,
            recovered: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl SynchronizationPhaseTrait for CatchUpRecoverBlockHeaderFromDbPhase {
    fn name(&self) -> &'static str { "CatchUpRecoverBlockHeaderFromDbPhase" }

    fn phase_type(&self) -> SyncPhaseType {
        SyncPhaseType::CatchUpRecoverBlockHeaderFromDB
    }

    fn next(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType
    {
        if self.recovered.load(AtomicOrdering::SeqCst) == false {
            return self.phase_type();
        }

        DynamicCapability::ServeHeaders(true).broadcast(io, &sync_handler.syn);
        SyncPhaseType::CatchUpSyncBlockHeader
    }

    fn start(
        &self, _io: &dyn NetworkContext,
        _sync_handler: &SynchronizationProtocolHandler,
    )
    {
        info!("start phase {:?}", self.name());
        self.recovered.store(false, AtomicOrdering::SeqCst);
        let recovered = self.recovered.clone();
        let graph = self.graph.clone();
        std::thread::spawn(move || {
            graph.recover_graph_from_db(true /* header_only */);
            recovered.store(true, AtomicOrdering::SeqCst);
            info!("finish recover header graph from db");
        });
    }
}

pub struct CatchUpSyncBlockHeaderPhase {
    pub syn: Arc<SynchronizationState>,
    pub graph: SharedSynchronizationGraph,
}

impl CatchUpSyncBlockHeaderPhase {
    pub fn new(
        syn: Arc<SynchronizationState>, graph: SharedSynchronizationGraph,
    ) -> Self {
        CatchUpSyncBlockHeaderPhase { syn, graph }
    }
}

impl SynchronizationPhaseTrait for CatchUpSyncBlockHeaderPhase {
    fn name(&self) -> &'static str { "CatchUpSyncBlockHeaderPhase" }

    fn phase_type(&self) -> SyncPhaseType {
        SyncPhaseType::CatchUpSyncBlockHeader
    }

    fn next(
        &self, _io: &dyn NetworkContext,
        _sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType
    {
        // FIXME: use target_height instead.
        let middle_epoch = self.syn.get_middle_epoch();
        if middle_epoch.is_none() {
            return self.phase_type();
        }
        let middle_epoch = middle_epoch.unwrap();
        // FIXME: OK, what if the chain height is close, or even local height is
        // FIXME: larger, but the chain forked earlier very far away?
        if self.graph.consensus.best_epoch_number()
            + CATCH_UP_EPOCH_LAG_THRESHOLD
            >= middle_epoch
        {
            return SyncPhaseType::CatchUpCheckpoint;
        }

        self.phase_type()
    }

    fn start(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        info!("start phase {:?}", self.name());
        let (_, cur_era_genesis_height) =
            self.graph.get_genesis_hash_and_height_in_current_era();
        *sync_handler.latest_epoch_requested.lock() = cur_era_genesis_height;

        sync_handler.request_initial_missed_block(io);
        sync_handler.request_epochs(io);
    }
}

pub struct CatchUpCheckpointPhase {
    state_sync: Arc<SnapshotChunkSync>,
    has_state: AtomicBool,
}

impl CatchUpCheckpointPhase {
    pub fn new(state_sync: Arc<SnapshotChunkSync>) -> Self {
        CatchUpCheckpointPhase {
            state_sync,
            has_state: AtomicBool::new(false),
        }
    }
}

impl SynchronizationPhaseTrait for CatchUpCheckpointPhase {
    fn name(&self) -> &'static str { "CatchUpCheckpointPhase" }

    fn phase_type(&self) -> SyncPhaseType { SyncPhaseType::CatchUpCheckpoint }

    fn next(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType
    {
        if self.has_state.load(AtomicOrdering::SeqCst) {
            return SyncPhaseType::CatchUpRecoverBlockFromDB;
        }

        let epoch_to_sync = sync_handler.graph.consensus.get_to_sync_epoch_id();
        match sync_handler
            .graph
            .consensus
            .get_trusted_blame_block_for_snapshot(&epoch_to_sync)
        {
            Some(trusted_blame_block) => {
                if self.state_sync.snapshot_epoch_id() == epoch_to_sync {
                    if self.state_sync.status() == Status::Completed {
                        DynamicCapability::ServeCheckpoint(Some(epoch_to_sync))
                            .broadcast(io, &sync_handler.syn);
                        self.state_sync.restore_execution_state(sync_handler);
                        *sync_handler
                            .graph
                            .consensus
                            .synced_epoch_id_and_blame_block
                            .lock() =
                            Some((epoch_to_sync, trusted_blame_block));
                        return SyncPhaseType::CatchUpRecoverBlockFromDB;
                    }
                } else {
                    // start to sync new checkpoint if new era started,
                    self.state_sync.start(
                        epoch_to_sync,
                        trusted_blame_block,
                        io,
                        sync_handler,
                    )
                }
            }
            None => {
                // FIXME should find the trusted blame block
                error!("failed to start checkpoint sync, the trusted blame block is unavailable");
            }
        }

        self.phase_type()
    }

    fn start(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        info!("start phase {:?}", self.name());
        let epoch_to_sync = sync_handler.graph.consensus.get_to_sync_epoch_id();

        let has_state = sync_handler
            .graph
            .data_man
            .get_epoch_execution_commitment_with_db(&epoch_to_sync)
            .is_some();
        if has_state {
            self.has_state.store(true, AtomicOrdering::SeqCst);
            return;
        }

        match sync_handler
            .graph
            .consensus
            .get_trusted_blame_block_for_snapshot(&epoch_to_sync)
        {
            Some(trusted_blame_block) => {
                info!("start to sync state for checkpoint {:?}, trusted blame block = {:?}", epoch_to_sync, trusted_blame_block);

                self.state_sync.start(
                    epoch_to_sync,
                    trusted_blame_block,
                    io,
                    sync_handler,
                );
            }
            None => {
                // FIXME should find the trusted blame block
                error!("failed to start checkpoint sync, the trusted blame block is unavailable");
                return;
            }
        }
    }
}

pub struct CatchUpRecoverBlockFromDbPhase {
    pub graph: SharedSynchronizationGraph,
    pub recovered: Arc<AtomicBool>,
}

impl CatchUpRecoverBlockFromDbPhase {
    pub fn new(graph: SharedSynchronizationGraph) -> Self {
        CatchUpRecoverBlockFromDbPhase {
            graph,
            recovered: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl SynchronizationPhaseTrait for CatchUpRecoverBlockFromDbPhase {
    fn name(&self) -> &'static str { "CatchUpRecoverBlockFromDbPhase" }

    fn phase_type(&self) -> SyncPhaseType {
        SyncPhaseType::CatchUpRecoverBlockFromDB
    }

    fn next(
        &self, _io: &dyn NetworkContext,
        _sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType
    {
        if self.recovered.load(AtomicOrdering::SeqCst) == false {
            return self.phase_type();
        }
        SyncPhaseType::CatchUpSyncBlock
    }

    fn start(
        &self, _io: &dyn NetworkContext,
        _sync_handler: &SynchronizationProtocolHandler,
    )
    {
        info!("start phase {:?}", self.name());
        {
            // Acquire the lock of synchronization graph first to make sure no
            // more blocks will be inserted into synchronization graph.
            let old_sync_inner = &mut *self.graph.inner.write();
            // Wait until all the graph ready blocks in queue are inserted into
            // consensus graph.
            while *self.graph.latest_graph_ready_block.lock()
                != *self.graph.consensus.latest_inserted_block.lock()
            {
                thread::sleep(time::Duration::from_millis(100));
            }
            // Now, we can safely acquire the lock of consensus graph.
            let old_consensus_inner = &mut *self.graph.consensus.inner.write();
            // We should assign a new instance_id here since we construct a new
            // consensus graph.
            old_sync_inner.data_man.initialize_instance_id();

            let (cur_era_genesis_hash, cur_era_genesis_height) =
                old_sync_inner.get_genesis_hash_and_height_in_current_era();

            // TODO: Make sure that the checkpoint will not change between the
            // end of CatchUpCheckpointPhase and the start of
            // CatchUpRecoverBlockFromDbPhase.

            let new_consensus_inner = ConsensusGraphInner::with_era_genesis(
                old_consensus_inner.pow_config.clone(),
                self.graph.data_man.clone(),
                old_consensus_inner.inner_conf.clone(),
                &cur_era_genesis_hash,
            );
            // For archive node, this will be `None`.
            // For full node, this is `None` when the state of checkpoint is
            // already in disk and we didn't sync it from peer.
            // In both cases, we should set `state_availability_boundary` to
            // `[cur_era_stable_height, cur_era_stable_height]`.
            if let Some((epoch_synced, trusted_blame_block)) =
                &*self.graph.consensus.synced_epoch_id_and_blame_block.lock()
            {
                let epoch_synced_height = self
                    .graph
                    .data_man
                    .block_header_by_hash(epoch_synced)
                    .expect("Header for checkpoint exists")
                    .height();
                *self.graph.data_man.state_availability_boundary.write() =
                    StateAvailabilityBoundary::new(
                        *epoch_synced,
                        epoch_synced_height,
                    );
                // This map will be used to recover `state_valid` info for each
                // pivot block before `trusted_blame_block`.
                let mut pivot_block_state_valid_map =
                    self.graph.consensus.pivot_block_state_valid_map.lock();
                let mut cur = *old_consensus_inner
                    .hash_to_arena_indices
                    .get(trusted_blame_block)
                    .unwrap();
                while cur != NULL {
                    let blame = self
                        .graph
                        .data_man
                        .block_header_by_hash(
                            &old_consensus_inner.arena[cur].hash,
                        )
                        .unwrap()
                        .blame();
                    for i in 0..blame + 1 {
                        trace!("Backup state_valid: hash={:?} height={} state_valid={},", old_consensus_inner.arena[cur].hash, old_consensus_inner.arena[cur].height,
                                   i == 0);
                        pivot_block_state_valid_map.insert(
                            old_consensus_inner.arena[cur].hash,
                            i == 0,
                        );
                        cur = old_consensus_inner.arena[cur].parent;
                        if cur == NULL {
                            break;
                        }
                    }
                }
            } else {
                let cur_era_stable_height = if cur_era_genesis_height == 0 {
                    0
                } else {
                    cur_era_genesis_height
                        + new_consensus_inner.inner_conf.era_epoch_count
                };
                let stable_epoch_set = self
                    .graph
                    .data_man
                    .epoch_set_hashes_from_db(cur_era_stable_height)
                    .expect("epoch set for stable must exist");
                let cur_era_stable_hash =
                    *stable_epoch_set.last().expect("nonempty");
                *self.graph.data_man.state_availability_boundary.write() =
                    StateAvailabilityBoundary::new(
                        cur_era_stable_hash,
                        cur_era_stable_height,
                    );
            }
            self.graph.consensus.update_best_info(&new_consensus_inner);
            *old_consensus_inner = new_consensus_inner;
            // FIXME: We may need to some information of `confirmation_meter`.
            self.graph.consensus.confirmation_meter.reset();
            let new_sync_inner = SynchronizationGraphInner::with_genesis_block(
                self.graph
                    .data_man
                    .block_header_by_hash(&cur_era_genesis_hash)
                    .expect("era genesis exists"),
                old_sync_inner.pow_config.clone(),
                old_sync_inner.config.clone(),
                old_sync_inner.data_man.clone(),
            );
            *old_sync_inner = new_sync_inner;

            self.graph
                .statistics
                .clear_sync_and_consensus_graph_statistics();
        }
        self.graph
            .consensus
            .txpool
            .notify_new_best_info(self.graph.consensus.best_info());

        self.recovered.store(false, AtomicOrdering::SeqCst);
        let recovered = self.recovered.clone();
        let graph = self.graph.clone();
        std::thread::Builder::new()
            .name("recover_blocks".into())
            .spawn(move || {
                graph.recover_graph_from_db(false /* header_only */);
                recovered.store(true, AtomicOrdering::SeqCst);
                info!("finish recover block graph from db");
            })
            .expect("Thread spawn failure");
    }
}

pub struct CatchUpSyncBlockPhase {
    pub syn: Arc<SynchronizationState>,
    pub graph: SharedSynchronizationGraph,
}

impl CatchUpSyncBlockPhase {
    pub fn new(
        syn: Arc<SynchronizationState>, graph: SharedSynchronizationGraph,
    ) -> Self {
        CatchUpSyncBlockPhase { syn, graph }
    }
}

impl SynchronizationPhaseTrait for CatchUpSyncBlockPhase {
    fn name(&self) -> &'static str { "CatchUpSyncBlockPhase" }

    fn phase_type(&self) -> SyncPhaseType { SyncPhaseType::CatchUpSyncBlock }

    fn next(
        &self, _io: &dyn NetworkContext,
        _sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType
    {
        // FIXME: use target_height instead.
        let middle_epoch = self.syn.get_middle_epoch();
        if middle_epoch.is_none() {
            if self.syn.is_dev_mode() {
                return SyncPhaseType::Normal;
            } else {
                return self.phase_type();
            }
        }
        let middle_epoch = middle_epoch.unwrap();
        // FIXME: OK, what if the chain height is close, or even local height is
        // FIXME: larger, but the chain forked earlier very far away?
        if self.graph.consensus.best_epoch_number()
            + CATCH_UP_EPOCH_LAG_THRESHOLD
            >= middle_epoch
        {
            return SyncPhaseType::Normal;
        }

        self.phase_type()
    }

    fn start(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        info!("start phase {:?}", self.name());

        let (_, cur_era_genesis_height) =
            self.graph.get_genesis_hash_and_height_in_current_era();
        *sync_handler.latest_epoch_requested.lock() = cur_era_genesis_height;

        sync_handler.request_initial_missed_block(io);
        sync_handler.request_epochs(io);
    }
}

pub struct NormalSyncPhase {}

impl NormalSyncPhase {
    pub fn new() -> Self { NormalSyncPhase {} }
}

impl SynchronizationPhaseTrait for NormalSyncPhase {
    fn name(&self) -> &'static str { "NormalSyncPhase" }

    fn phase_type(&self) -> SyncPhaseType { SyncPhaseType::Normal }

    fn next(
        &self, _io: &dyn NetworkContext,
        _sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType
    {
        // FIXME: handle the case where we need to switch back phase
        self.phase_type()
    }

    fn start(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        info!("start phase {:?}", self.name());
        sync_handler.request_missing_terminals(io);
    }
}
