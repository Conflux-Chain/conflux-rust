// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::DynamicCapability,
    state::{SnapshotChunkSync, Status},
    synchronization_protocol_handler::SynchronizationProtocolHandler,
    synchronization_state::SynchronizationState,
    SharedSynchronizationGraph,
};
use cfx_internal_common::StateAvailabilityBoundary;
use cfx_parameters::sync::CATCH_UP_EPOCH_LAG_THRESHOLD;
use network::NetworkContext;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    },
    thread,
    time::{self, Instant},
};

///
/// Archive node goes through the following phases:
///     CatchUpFillBlockBody --> CatchUpSyncBlock --> Normal
///
/// Full node goes through the following phases:
///     CatchUpRecoverBlockHeaderFromDB --> CatchUpSyncBlockHeader -->
///     CatchUpCheckpoint --> CatchUpFillBlockBody -->
///     CatchUpSyncBlock --> Normal

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum SyncPhaseType {
    CatchUpRecoverBlockHeaderFromDB = 0,
    CatchUpSyncBlockHeader = 1,
    CatchUpCheckpoint = 2,
    CatchUpFillBlockBodyPhase = 3,
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
        sync_manager.register_phase(Arc::new(CatchUpFillBlockBodyPhase::new(
            sync_graph.clone(),
        )));
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
            graph.recover_graph_from_db();
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
        let median_epoch = match self.syn.median_epoch_from_normal_peers() {
            None => {
                return if self.syn.allow_phase_change_without_peer() {
                    SyncPhaseType::CatchUpCheckpoint
                } else {
                    self.phase_type()
                }
            }
            Some(epoch) => epoch,
        };
        debug!(
            "best_epoch: {}, peer median: {}",
            self.graph.consensus.best_epoch_number(),
            median_epoch
        );
        // FIXME: OK, what if the chain height is close, or even local height is
        // FIXME: larger, but the chain forked earlier very far away?
        if self.graph.consensus.catch_up_completed(median_epoch) {
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
        *sync_handler.latest_epoch_requested.lock() =
            (cur_era_genesis_height, Instant::now());

        sync_handler.request_epochs(io);
    }
}

pub struct CatchUpCheckpointPhase {
    state_sync: Arc<SnapshotChunkSync>,

    /// Is `true` if we have the state locally and do not need to sync
    /// checkpoints. Only set when the phase starts.
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
            return SyncPhaseType::CatchUpFillBlockBodyPhase;
        }
        let epoch_to_sync = sync_handler.graph.consensus.get_to_sync_epoch_id();
        let current_era_genesis = sync_handler
            .graph
            .data_man
            .get_cur_consensus_era_genesis_hash();
        self.state_sync.update_status(
            current_era_genesis,
            epoch_to_sync,
            io,
            sync_handler,
        );
        if self.state_sync.status() == Status::Completed {
            self.state_sync.restore_execution_state(sync_handler);
            *sync_handler.synced_epoch_id.lock() = Some(epoch_to_sync);
            SyncPhaseType::CatchUpFillBlockBodyPhase
        } else {
            self.phase_type()
        }
    }

    fn start(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        info!("start phase {:?}", self.name());
        sync_handler.graph.inner.write().locked_for_catchup = true;
        while sync_handler.graph.is_consensus_worker_busy() {
            thread::sleep(time::Duration::from_millis(100));
        }
        let current_era_genesis = sync_handler
            .graph
            .data_man
            .get_cur_consensus_era_genesis_hash();
        let epoch_to_sync = sync_handler.graph.consensus.get_to_sync_epoch_id();

        if let Some(commitment) = sync_handler
            .graph
            .data_man
            .load_epoch_execution_commitment_from_db(&epoch_to_sync)
        {
            info!("CatchUpCheckpointPhase: commitment for epoch {:?} exists, skip state sync. \
                commitment={:?}", epoch_to_sync, commitment);
            self.has_state.store(true, AtomicOrdering::SeqCst);

            // TODO Here has_state could mean we have the snapshot of the state
            // or the last snapshot and the delta mpt. We only need to specially
            // handle the case of snapshot-only state where we
            // cannot compute state_valid because we do not have a
            // valid state root.
            if epoch_to_sync != sync_handler.graph.data_man.true_genesis.hash()
            {
                *sync_handler.synced_epoch_id.lock() = Some(epoch_to_sync);
            }
            return;
        }

        self.state_sync.update_status(
            current_era_genesis,
            epoch_to_sync,
            io,
            sync_handler,
        );
    }
}

pub struct CatchUpFillBlockBodyPhase {
    pub graph: SharedSynchronizationGraph,
}

impl CatchUpFillBlockBodyPhase {
    pub fn new(graph: SharedSynchronizationGraph) -> Self {
        CatchUpFillBlockBodyPhase { graph }
    }
}

impl SynchronizationPhaseTrait for CatchUpFillBlockBodyPhase {
    fn name(&self) -> &'static str { "CatchUpFillBlockBodyPhase" }

    fn phase_type(&self) -> SyncPhaseType {
        SyncPhaseType::CatchUpFillBlockBodyPhase
    }

    fn next(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType
    {
        if self.graph.is_fill_block_completed() {
            if self.graph.complete_filling_block_bodies() {
                return SyncPhaseType::CatchUpSyncBlock;
            } else {
                // consensus graph is reconstructed and we need to request more
                // bodies
                sync_handler.request_block_bodies(io)
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
        {
            // For archive node, this will be `None`.
            // For full node, this is `None` when the state of checkpoint is
            // already in disk and we didn't sync it from peer.
            // In both cases, we should set `state_availability_boundary` to
            // `[cur_era_stable_height, cur_era_stable_height]`.
            if let Some(epoch_synced) = &*sync_handler.synced_epoch_id.lock() {
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
                self.graph
                    .data_man
                    .state_availability_boundary
                    .write()
                    .set_synced_state_height(epoch_synced_height);
            } else {
                let cur_era_stable_hash =
                    self.graph.data_man.get_cur_consensus_era_stable_hash();
                let cur_era_stable_height = self
                    .graph
                    .data_man
                    .block_header_by_hash(&cur_era_stable_hash)
                    .expect("stable era block header must exist")
                    .height();
                *self.graph.data_man.state_availability_boundary.write() =
                    StateAvailabilityBoundary::new(
                        cur_era_stable_hash,
                        cur_era_stable_height,
                    );
            }
            self.graph.inner.write().block_to_fill_set =
                self.graph.consensus.get_blocks_needing_bodies();
            sync_handler.request_block_bodies(io);
        }
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
        sync_handler: &SynchronizationProtocolHandler,
    ) -> SyncPhaseType
    {
        // FIXME: use target_height instead.
        let median_epoch = match self.syn.median_epoch_from_normal_peers() {
            None => {
                return if self.syn.allow_phase_change_without_peer() {
                    sync_handler.graph.consensus.enter_normal_phase();
                    SyncPhaseType::Normal
                } else {
                    self.phase_type()
                }
            }
            Some(epoch) => epoch,
        };
        // FIXME: OK, what if the chain height is close, or even local height is
        // FIXME: larger, but the chain forked earlier very far away?
        if self.graph.consensus.best_epoch_number()
            + CATCH_UP_EPOCH_LAG_THRESHOLD
            >= median_epoch
        {
            sync_handler.graph.consensus.enter_normal_phase();
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
        *sync_handler.latest_epoch_requested.lock() =
            (cur_era_genesis_height, Instant::now());

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
