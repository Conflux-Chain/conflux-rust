// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    parameters::consensus_internal::REWARD_EPOCH_COUNT,
    storage::{
        storage_db::SnapshotInfo, Result as StorageResult, StateRootWithAuxInfo,
    },
    sync::{
        error::{Error, ErrorKind},
        message::{
            msgid, Context, SnapshotManifestRequest, SnapshotManifestResponse,
            StateSyncCandidateRequest,
        },
        state::{
            state_sync_candidate::state_sync_candidate_manager::StateSyncCandidateManager,
            state_sync_chunk::snapshot_chunk_manager::{
                SnapshotChunkConfig, SnapshotChunkManager,
            },
            state_sync_manifest::snapshot_manifest_manager::SnapshotManifestManager,
            storage::{Chunk, ChunkKey, SnapshotSyncCandidate},
        },
        synchronization_state::PeerFilter,
        SynchronizationProtocolHandler,
    },
};
use cfx_types::H256;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use primitives::{BlockReceipts, EpochId};
use rand::{seq::SliceRandom, thread_rng};
use std::{
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
    sync_candidate_manager: StateSyncCandidateManager,

    /// The checkpoint whose state is being synced
    manifest_request_status: Option<(Instant, NodeId)>,

    current_sync_candidate: Option<SnapshotSyncCandidate>,
    trusted_blame_block: H256,
    status: Status,

    /// State root verified by blame.
    true_state_root_by_blame_info: StateRootWithAuxInfo,
    /// Point to the corresponding entry to the snapshot in the blame vectors.
    blame_vec_offset: usize,
    receipt_blame_vec: Vec<H256>,
    bloom_blame_vec: Vec<H256>,
    epoch_receipts: Vec<(H256, H256, Arc<BlockReceipts>)>,
    snapshot_info: SnapshotInfo,

    // Initialized after we receive a valid manifest.
    chunk_manager: Option<SnapshotChunkManager>,
}

impl Default for Inner {
    fn default() -> Self {
        Self::new(None, Default::default(), Default::default())
    }
}

impl Inner {
    fn new(
        current_sync_candidate: Option<SnapshotSyncCandidate>,
        trusted_blame_block: H256, status: Status,
    ) -> Self
    {
        Self {
            sync_candidate_manager: Default::default(),
            manifest_request_status: None,
            current_sync_candidate,
            trusted_blame_block,
            status,
            true_state_root_by_blame_info: StateRootWithAuxInfo::genesis(
                &Default::default(),
            ),
            snapshot_info: SnapshotInfo::genesis_snapshot_info(),
            receipt_blame_vec: Default::default(),
            bloom_blame_vec: Default::default(),
            epoch_receipts: Default::default(),
            chunk_manager: None,
            blame_vec_offset: 0,
        }
    }

    pub fn start_sync_for_candidate(
        &mut self, sync_candidate: SnapshotSyncCandidate,
        trusted_blame_block: H256, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        if let Some(chunk_manager) = &mut self.chunk_manager {
            if chunk_manager.snapshot_candidate() == &sync_candidate
                && self.trusted_blame_block == trusted_blame_block
            {
                // The new candidate is not changed, so we can resume our
                // previous sync status with new `active_peers`.
                self.status = Status::DownloadingChunks(Instant::now());
                chunk_manager.add_active_peers(
                    self.sync_candidate_manager.active_peers(),
                );
                return;
            }
        }
        info!(
            "start to sync state, snapshot_to_sync = {:?}, trusted blame block = {:?}",
            sync_candidate, trusted_blame_block);
        let old_inner = std::mem::replace(
            self,
            Self::new(
                Some(sync_candidate),
                trusted_blame_block,
                Status::DownloadingManifest(Instant::now()),
            ),
        );
        self.sync_candidate_manager = old_inner.sync_candidate_manager;
        self.request_manifest(io, sync_handler);
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

    /// request manifest from random peer
    fn request_manifest(
        &mut self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        let request = SnapshotManifestRequest::new(
            // Safe to unwrap since it's guaranteed to be Some(..)
            self.current_sync_candidate.clone().unwrap(),
            self.trusted_blame_block.clone(),
        );

        let available_peers = PeerFilter::new(msgid::GET_SNAPSHOT_MANIFEST)
            .choose_from(self.sync_candidate_manager.active_peers())
            .select_all(&sync_handler.syn);
        let maybe_peer = available_peers.choose(&mut thread_rng()).map(|p| *p);
        if let Some(peer) = maybe_peer {
            self.manifest_request_status = Some((Instant::now(), peer));
            sync_handler.request_manager.request_with_delay(
                io,
                Box::new(request),
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
            "(status = {:?}, pending_peers: {}, active_peers: {}, chunks: {:?})",
            self.status,
            self.sync_candidate_manager.pending_peers().len(),
            self.sync_candidate_manager.active_peers().len(),
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

        // new era started
        if Some(&request.snapshot_to_sync)
            != inner.current_sync_candidate.as_ref()
        {
            info!(
                "The received snapshot manifest doesn't match the current sync candidate,\
                 current sync candidate = {:?}, requested sync candidate = {:?}",
                inner.current_sync_candidate,
                request.snapshot_to_sync);
            return Ok(());
        }

        // status mismatch
        let start_time = match inner.status {
            Status::DownloadingManifest(start_time) => start_time,
            _ => {
                info!("Snapshot manifest received, but mismatch with current status {:?}", inner.status);
                return Ok(());
            }
        };

        // validate blame state if requested
        if request.is_initial_request() {
            match SnapshotManifestManager::validate_blame_states(
                ctx,
                inner
                    .current_sync_candidate
                    .as_ref()
                    .unwrap()
                    .get_snapshot_epoch_id(),
                &inner.trusted_blame_block,
                &response.state_root_vec,
                &response.receipt_blame_vec,
                &response.bloom_blame_vec,
            ) {
                Some((
                    blame_vec_offset,
                    state_root_with_aux_info,
                    snapshot_info,
                )) => {
                    // TODO: debug only check. can be removed later.
                    if response.snapshot_merkle_root
                        != snapshot_info.merkle_root
                    {
                        warn!(
                            "ManifestResponse has invalid snapshot_root: got {:?} should be {:?}",
                            response.snapshot_merkle_root,
                            snapshot_info.merkle_root);
                        self.resync_manifest(ctx, &mut inner);
                        bail!(ErrorKind::InvalidSnapshotManifest(
                            "invalid snapshot root in manifest".into(),
                        ));
                    }
                    inner.true_state_root_by_blame_info =
                        state_root_with_aux_info;
                    inner.blame_vec_offset = blame_vec_offset;
                    inner.snapshot_info = snapshot_info;
                }
                None => {
                    warn!("failed to validate the blame state, re-sync manifest from other peer");
                    self.resync_manifest(ctx, &mut inner);
                    bail!(ErrorKind::InvalidSnapshotManifest(
                        "invalid blame state in manifest".into(),
                    ));
                }
            }
            match SnapshotManifestManager::validate_epoch_receipts(
                ctx,
                inner.blame_vec_offset,
                inner
                    .current_sync_candidate
                    .as_ref()
                    .unwrap()
                    .get_snapshot_epoch_id(),
                &response.receipt_blame_vec,
                &response.bloom_blame_vec,
                &response.block_receipts,
            ) {
                Some(epoch_receipts) => inner.epoch_receipts = epoch_receipts,
                None => {
                    warn!("failed to validate the epoch receipts, re-sync manifest from other peer");
                    self.resync_manifest(ctx, &mut inner);
                    bail!(ErrorKind::InvalidSnapshotManifest(
                        "invalid epoch receipts in manifest".into(),
                    ));
                }
            }

            // Check proofs for keys.
            if let Err(e) = response.manifest.validate(
                &inner.snapshot_info.merkle_root,
                &request.start_chunk,
            ) {
                warn!("failed to validate snapshot manifest, error = {:?}", e);
                bail!(ErrorKind::InvalidSnapshotManifest(
                    "invalid chunk proofs in manifest".into(),
                ));
            }
        }

        // FIXME Handle next_chunk

        //        let next_chunk = response.manifest.next_chunk();
        //        // continue to request remaining manifest if any
        //        if let Some(next_chunk) = next_chunk {
        //            let request =
        // SnapshotManifestRequest::new_with_start_chunk(
        // inner.snapshot_epoch_id.clone(),                next_chunk,
        //            );
        //            ctx.manager.request_manager.request_with_delay(
        //                ctx.io,
        //                Box::new(request),
        //                Some(ctx.peer),
        //                None,
        //            );
        //            return;
        //        }

        // todo validate the integrity of manifest, and re-sync it if failed

        info!(
            "Snapshot manifest received, checkpoint = {:?}, elapsed = {:?}",
            inner.current_sync_candidate,
            start_time.elapsed(),
        );

        // update status
        inner.status = Status::DownloadingChunks(Instant::now());
        inner.manifest_request_status = None;
        inner.receipt_blame_vec = response.receipt_blame_vec;
        inner.bloom_blame_vec = response.bloom_blame_vec;
        inner.chunk_manager = Some(SnapshotChunkManager::new_and_start(
            ctx,
            inner.current_sync_candidate.clone().unwrap(),
            inner.snapshot_info.clone(),
            response.manifest,
            inner.sync_candidate_manager.active_peers().clone(),
            self.config.chunk_config(),
        )?);

        debug!("sync state progress: {:?}", *inner);
        Ok(())
    }

    fn resync_manifest(&self, ctx: &Context, inner: &mut Inner) {
        inner.request_manifest(ctx.io, ctx.manager);
    }

    pub fn handle_snapshot_chunk_response(
        &self, ctx: &Context, chunk_key: ChunkKey, chunk: Chunk,
    ) -> StorageResult<()> {
        let mut inner = self.inner.write();
        if let Some(chunk_manager) = &mut inner.chunk_manager {
            if chunk_manager.add_chunk(ctx, chunk_key, chunk)? {
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
        let mut deferred_block_hash = inner
            .current_sync_candidate
            .as_ref()
            .unwrap()
            .get_snapshot_epoch_id()
            .clone();
        // FIXME: Because state_root_aux_info can't be computed for state block
        // FIXME: before snapshot, for the reward epoch count, maybe
        // FIXME: save it to a dedicated place for reward computation.
        for i in inner.blame_vec_offset
            ..(inner.blame_vec_offset + REWARD_EPOCH_COUNT as usize)
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
                    inner.true_state_root_by_blame_info.clone(),
                    inner.receipt_blame_vec[i],
                    inner.bloom_blame_vec[i],
                );
            let block = sync_handler
                .graph
                .data_man
                .block_header_by_hash(&deferred_block_hash)
                .unwrap();
            deferred_block_hash = *block.parent_hash();
        }
        for (block_hash, epoch_hash, receipts) in &inner.epoch_receipts {
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
                Status::DownloadingManifest(_)
                | Status::DownloadingChunks(_) => {
                    if inner.sync_candidate_manager.active_peers().is_empty() {
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
            {
                // We are requesting candidates and all `pending_peers` timeout,
                // or we are syncing states all
                // `active_peers` for all candidates timeout.
                warn!("current sync candidate becomes inactive: {:?}", inner);
                inner.status = Status::Inactive;
            }
            // We need to start/restart syncing states for a candidate.
            if inner.status == Status::StartCandidateSync {
                if let Some(sync_candidate) =
                    inner.sync_candidate_manager.get_active_candidate()
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
                                trusted_blame_block,
                                io,
                                sync_handler,
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
        if let Some((manifest_start_time, peer)) =
            &inner.manifest_request_status.clone()
        {
            if manifest_start_time.elapsed()
                > self.config.manifest_request_timeout
            {
                inner.sync_candidate_manager.note_state_sync_failure(peer);
                inner.manifest_request_status = None;
                inner.request_manifest(ctx.io, ctx.manager);
            }
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
}
