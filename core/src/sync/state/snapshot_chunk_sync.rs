// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    parameters::consensus_internal::REWARD_EPOCH_COUNT,
    storage::Result as StorageResult,
    sync::{
        error::Error,
        message::{
            msgid, Context, SnapshotManifestRequest, SnapshotManifestResponse,
            StateSyncCandidateRequest,
        },
        state::{
            state_sync_candidate::state_sync_candidate_manager::StateSyncCandidateManager,
            state_sync_chunk::snapshot_chunk_manager::{
                SnapshotChunkConfig, SnapshotChunkManager,
            },
            state_sync_manifest::snapshot_manifest_manager::{
                RelatedData, SnapshotManifestConfig, SnapshotManifestManager,
            },
            storage::{Chunk, ChunkKey, SnapshotSyncCandidate},
        },
        synchronization_state::PeerFilter,
        SynchronizationProtocolHandler,
    },
};
use cfx_types::H256;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use primitives::EpochId;
use std::{
    collections::HashSet,
    fmt::{Debug, Formatter},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Copy, Clone, PartialEq)]
pub enum Status {
    Inactive,
    RequestingCandidates,
    StartCandidateSync,
    DownloadingManifest(Instant),
    DownloadingChunks(Instant),
    Completed,
    Invalid,
}

impl Default for Status {
    fn default() -> Self { Status::Inactive }
}

impl Debug for Status {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let status = match self {
            Status::Inactive => "inactive".into(),
            Status::RequestingCandidates => "requesting candidates".into(),
            Status::StartCandidateSync => {
                "about to request a candidate state".into()
            }
            Status::DownloadingManifest(t) => {
                format!("downloading manifest ({:?})", t.elapsed())
            }
            Status::DownloadingChunks(t) => {
                format!("downloading chunks ({:?})", t.elapsed())
            }
            Status::Completed => "completed".into(),
            Status::Invalid => "invalid".into(),
        };

        write!(f, "{}", status)
    }
}

// TODO: Implement OneStepSync / IncSync as this is currently only implemented
// for FullSync.
struct Inner {
    status: Status,

    sync_candidate_manager: StateSyncCandidateManager,
    // Initialized after we receive a valid manifest.
    chunk_manager: Option<SnapshotChunkManager>,
    manifest_manager: Option<SnapshotManifestManager>,

    related_data: Option<RelatedData>,
}

impl Default for Inner {
    fn default() -> Self { Self::new() }
}

impl Inner {
    fn new() -> Self {
        Self {
            sync_candidate_manager: Default::default(),
            status: Status::Inactive,
            related_data: None,
            chunk_manager: None,
            manifest_manager: None,
        }
    }

    pub fn start_sync_for_candidate(
        &mut self, sync_candidate: SnapshotSyncCandidate,
        active_peers: HashSet<NodeId>, trusted_blame_block: H256,
        io: &dyn NetworkContext, sync_handler: &SynchronizationProtocolHandler,
        manifest_config: SnapshotManifestConfig,
    )
    {
        if let Some(chunk_manager) = &mut self.chunk_manager {
            if chunk_manager.snapshot_candidate == sync_candidate {
                // TODO If the chunk manager does not make progress for a long
                // time, we should also resync the manifest,
                // because the manifest might be valid but also
                // malicious. For example, the chunk size might be larger than
                // MaxPacketSize so no one can return us that chunk.

                // The new candidate is not changed, so we can resume our
                // previous sync status with new `active_peers`.
                self.status = Status::DownloadingChunks(Instant::now());
                chunk_manager.set_active_peers(active_peers);
                return;
            }
        }
        info!(
            "start to sync state, snapshot_to_sync = {:?}, trusted blame block = {:?}",
            sync_candidate, trusted_blame_block);
        let manifest_manager = SnapshotManifestManager::new_and_start(
            sync_candidate,
            trusted_blame_block,
            active_peers,
            manifest_config,
            io,
            sync_handler,
        );
        self.manifest_manager = Some(manifest_manager);
        self.status = Status::DownloadingManifest(Instant::now());
    }

    pub fn start_sync(
        &mut self, current_era_genesis: EpochId,
        candidates: Vec<SnapshotSyncCandidate>, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        let peers = PeerFilter::new(msgid::STATE_SYNC_CANDIDATE_REQUEST)
            .select_all(&sync_handler.syn);
        if peers.is_empty() {
            return;
        }
        self.status = Status::RequestingCandidates;
        self.sync_candidate_manager.reset(
            current_era_genesis,
            candidates.clone(),
            peers.clone(),
        );
        self.request_candidates(io, sync_handler, candidates, peers);
    }

    /// request state candidates from all peers
    fn request_candidates(
        &self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
        candidates: Vec<SnapshotSyncCandidate>, peers: Vec<NodeId>,
    )
    {
        let request = StateSyncCandidateRequest {
            request_id: 0,
            candidates,
        };
        for peer in peers {
            sync_handler.request_manager.request_with_delay(
                io,
                Box::new(request.clone()),
                Some(peer),
                None,
            );
        }
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "(status = {:?}, pending_peers: {}, manifest: {:?}, chunks: {:?})",
            self.status,
            self.sync_candidate_manager.pending_peers().len(),
            self.manifest_manager,
            self.chunk_manager,
        )
    }
}

pub struct SnapshotChunkSync {
    inner: Arc<RwLock<Inner>>,
    config: StateSyncConfiguration,
}

impl SnapshotChunkSync {
    pub fn new(config: StateSyncConfiguration) -> Self {
        SnapshotChunkSync {
            inner: Default::default(),
            config,
        }
    }

    pub fn status(&self) -> Status { self.inner.read().status }

    pub fn handle_snapshot_manifest_response(
        &self, ctx: &Context, response: SnapshotManifestResponse,
        request: &SnapshotManifestRequest,
    ) -> Result<(), Error>
    {
        let mut inner = &mut *self.inner.write();

        // status mismatch
        if !matches!(inner.status, Status::DownloadingManifest(_)) {
            info!("Snapshot manifest received, but mismatch with current status {:?}", inner.status);
            return Ok(());
        };
        if let Some(manifest_manager) = &mut inner.manifest_manager {
            let r = manifest_manager
                .handle_snapshot_manifest_response(ctx, response, request)?;
            if let Some(related_data) = r {
                // update status
                inner.status = Status::DownloadingChunks(Instant::now());
                inner.chunk_manager =
                    Some(SnapshotChunkManager::new_and_start(
                        ctx,
                        manifest_manager.snapshot_candidate.clone(),
                        related_data.snapshot_info.clone(),
                        manifest_manager.chunk_boundaries.clone(),
                        manifest_manager.chunk_boundary_proofs.clone(),
                        manifest_manager.active_peers.clone(),
                        self.config.chunk_config(),
                    )?);
                inner.related_data = Some(related_data);
            }
            debug!("sync state progress: {:?}", *inner);
        } else {
            error!("manifest manager is None in status {:?}", inner.status);
        }
        if matches!(inner.status, Status::DownloadingChunks(_)) {
            inner.manifest_manager = None;
        }
        Ok(())
    }

    pub fn handle_snapshot_chunk_response(
        &self, ctx: &Context, chunk_key: ChunkKey, chunk: Chunk,
    ) -> StorageResult<()> {
        let mut inner = self.inner.write();

        if !matches!(inner.status, Status::DownloadingChunks(_)) {
            info!("Snapshot chunk {:?} received, but mismatch with current status {:?}",
                chunk_key, inner.status);
            return Ok(());
        }

        if let Some(chunk_manager) = &mut inner.chunk_manager {
            if chunk_manager.add_chunk(ctx, chunk_key, chunk)? {
                // Once the status becomes Completed, it will never be changed
                // to another status, and all the related fields
                // (snapshot_id, trust_blame_block, receipts, e.t.c.)
                // of Inner will not be modified, because we return early in
                // `update_status`
                // and `handle_snapshot_manifest_response`. Thus, we can rely on
                // the phase changing thread
                // to call `restore_execution_state` later safely.
                inner.status = Status::Completed;
            }
        } else {
            debug!(
                "Chunk {:?} received in status {:?}",
                chunk_key, inner.status
            );
        }
        info!("sync state progress: {:?}", *inner);
        Ok(())
    }

    pub fn restore_execution_state(
        &self, sync_handler: &SynchronizationProtocolHandler,
    ) {
        let inner = self.inner.read();
        let related_data = inner
            .related_data
            .as_ref()
            .expect("Set after receving manifest");
        let mut deferred_block_hash =
            related_data.snapshot_info.get_snapshot_epoch_id().clone();
        // FIXME: Because state_root_aux_info can't be computed for state block
        // FIXME: before snapshot, for the reward epoch count, maybe
        // FIXME: save it to a dedicated place for reward computation.
        for i in related_data.blame_vec_offset
            ..(related_data.blame_vec_offset + REWARD_EPOCH_COUNT as usize)
        {
            info!(
                "insert_epoch_execution_commitment for block hash {:?}",
                &deferred_block_hash
            );
            sync_handler
                .graph
                .data_man
                .insert_epoch_execution_commitment(
                    deferred_block_hash,
                    // FIXME: the state root is wrong for epochs before sync
                    // FIXME: point. but these information won't be used.
                    related_data.true_state_root_by_blame_info.clone(),
                    related_data.receipt_blame_vec[i],
                    related_data.bloom_blame_vec[i],
                );
            let block = sync_handler
                .graph
                .data_man
                .block_header_by_hash(&deferred_block_hash)
                .unwrap();
            deferred_block_hash = *block.parent_hash();
        }
        for (block_hash, epoch_hash, receipts) in &related_data.epoch_receipts {
            sync_handler.graph.data_man.insert_block_execution_result(
                *block_hash,
                *epoch_hash,
                receipts.clone(),
                true, /* persistent */
            );
        }
    }

    /// TODO Handling manifest requesting separately
    /// Return Some if a candidate is ready and we can start requesting
    /// manifests
    pub fn handle_snapshot_candidate_response(
        &self, peer: &NodeId,
        supported_candidates: &Vec<SnapshotSyncCandidate>,
        requested_candidates: &Vec<SnapshotSyncCandidate>,
    )
    {
        self.inner.write().sync_candidate_manager.on_peer_response(
            peer,
            supported_candidates,
            requested_candidates,
        )
    }

    pub fn on_peer_disconnected(&self, peer: &NodeId) {
        let mut inner = self.inner.write();
        inner.sync_candidate_manager.on_peer_disconnected(peer);
        if let Some(manifest_manager) = &mut inner.manifest_manager {
            manifest_manager.on_peer_disconnected(peer);
        }
        if let Some(chunk_manager) = &mut inner.chunk_manager {
            chunk_manager.on_peer_disconnected(peer);
        }
    }

    /// Reset status if we cannot make progress based on current peers and
    /// candidates
    pub fn update_status(
        &self, current_era_genesis: EpochId, epoch_to_sync: EpochId,
        io: &dyn NetworkContext, sync_handler: &SynchronizationProtocolHandler,
    )
    {
        let mut inner = self.inner.write();
        debug!("sync state status before updating: {:?}", *inner);
        self.check_timeout(
            &mut *inner,
            &Context {
                // node_id is not used here
                node_id: Default::default(),
                io,
                manager: sync_handler,
            },
        );

        // If we moves into the next era, we should force state_sync to change
        // the candidates to states with in the new stable era. If the
        // era stays the same and a new snapshot becomes available, we
        // only change candidates if old candidates cannot to be synced,
        // so a state can be synced with one era time instead of only
        // one snapshot time
        if inner.sync_candidate_manager.current_era_genesis
            == current_era_genesis
        {
            match inner.status {
                Status::Completed => return,
                Status::RequestingCandidates => {
                    if inner.sync_candidate_manager.pending_peers().is_empty() {
                        inner.status = Status::StartCandidateSync;
                        inner.sync_candidate_manager.set_active_candidate();
                    }
                }
                Status::DownloadingManifest(_) => {
                    if inner
                        .manifest_manager
                        .as_ref()
                        .expect("always set in DownloadingManifest")
                        .is_inactive()
                    {
                        // The current candidate fails, so try to choose the
                        // next one.
                        inner.status = Status::StartCandidateSync;
                        inner.sync_candidate_manager.set_active_candidate();
                    }
                }
                Status::DownloadingChunks(_) => {
                    if inner
                        .chunk_manager
                        .as_ref()
                        .expect("always set in DownloadingChunks")
                        .is_inactive()
                    {
                        // The current candidate fails, so try to choose the
                        // next one.
                        inner.status = Status::StartCandidateSync;
                        inner.sync_candidate_manager.set_active_candidate();
                    }
                }
                _ => {}
            }
            if inner.sync_candidate_manager.is_inactive()
                && inner
                    .chunk_manager
                    .as_ref()
                    .map_or(true, |m| m.is_inactive())
                && inner
                    .manifest_manager
                    .as_ref()
                    .map_or(true, |m| m.is_inactive())
            {
                // We are requesting candidates and all `pending_peers` timeout,
                // or we are syncing states and all
                // `active_peers` for all candidates timeout.
                warn!("current sync candidate becomes inactive: {:?}", inner);
                inner.status = Status::Inactive;
                inner.manifest_manager = None;
            }
            // We need to start/restart syncing states for a candidate.
            if inner.status == Status::StartCandidateSync {
                if let Some((sync_candidate, active_peers)) = inner
                    .sync_candidate_manager
                    .get_active_candidate_and_peers()
                {
                    match sync_handler
                        .graph
                        .consensus
                        .get_trusted_blame_block_for_snapshot(
                            sync_candidate.get_snapshot_epoch_id(),
                        ) {
                        Some(trusted_blame_block) => {
                            inner.start_sync_for_candidate(
                                sync_candidate,
                                active_peers,
                                trusted_blame_block,
                                io,
                                sync_handler,
                                self.config.manifest_config(),
                            );
                        }
                        None => {
                            error!("failed to start checkpoint sync, the trusted blame block is unavailable, epoch_to_sync={:?}", epoch_to_sync);
                        }
                    }
                } else {
                    inner.status = Status::Inactive;
                }
            }
        } else {
            inner.status = Status::Inactive;
        }

        if inner.status == Status::Inactive {
            // New era started or all candidates fail, we should restart
            // candidates sync
            let height = sync_handler
                .graph
                .data_man
                .block_header_by_hash(&epoch_to_sync)
                .expect("Syncing checkpoint should have available header")
                .height();
            let candidates = vec![SnapshotSyncCandidate::FullSync {
                height,
                snapshot_epoch_id: epoch_to_sync,
            }];
            inner.start_sync(current_era_genesis, candidates, io, sync_handler)
        }
        debug!("sync state status after updating: {:?}", *inner);
    }

    fn check_timeout(&self, inner: &mut Inner, ctx: &Context) {
        inner
            .sync_candidate_manager
            .check_timeout(&self.config.candidate_request_timeout);
        if let Some(manifest_manager) = &mut inner.manifest_manager {
            manifest_manager.check_timeout(ctx);
        }
        if let Some(chunk_manager) = &mut inner.chunk_manager {
            chunk_manager.check_timeout(ctx);
        }
    }
}

pub struct StateSyncConfiguration {
    pub max_downloading_chunks: usize,
    pub candidate_request_timeout: Duration,
    pub chunk_request_timeout: Duration,
    pub manifest_request_timeout: Duration,
}

impl StateSyncConfiguration {
    fn chunk_config(&self) -> SnapshotChunkConfig {
        SnapshotChunkConfig {
            max_downloading_chunks: self.max_downloading_chunks,
            chunk_request_timeout: self.chunk_request_timeout,
        }
    }

    fn manifest_config(&self) -> SnapshotManifestConfig {
        SnapshotManifestConfig {
            manifest_request_timeout: self.manifest_request_timeout,
        }
    }
}
