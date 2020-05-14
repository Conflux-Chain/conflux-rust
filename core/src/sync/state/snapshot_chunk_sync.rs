// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockExecutionResult,
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        consensus_internal::REWARD_EPOCH_COUNT,
    },
    storage::{
        storage_db::SnapshotInfo, FullSyncVerifier, Result as StorageResult,
        StateRootAuxInfo, StateRootWithAuxInfo,
    },
    sync::{
        error::{Error, ErrorKind},
        message::{msgid, Context},
        state::{
            restore::Restorer,
            snapshot_chunk_request::SnapshotChunkRequest,
            snapshot_manifest_request::SnapshotManifestRequest,
            snapshot_manifest_response::SnapshotManifestResponse,
            state_sync_candidate_manager::StateSyncCandidateManager,
            storage::{Chunk, ChunkKey, SnapshotSyncCandidate},
            StateSyncCandidateRequest,
        },
        synchronization_state::PeerFilter,
        SynchronizationProtocolHandler,
    },
};
use cfx_types::H256;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use primitives::{
    BlockHeaderBuilder, BlockReceipts, EpochId, EpochNumber, StateRoot,
    StorageKey, NULL_EPOCH,
};
use rand::{seq::SliceRandom, thread_rng};
use std::{
    collections::{HashMap, VecDeque},
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

    pending_chunks: VecDeque<ChunkKey>,
    /// status of downloading chunks
    downloading_chunks: HashMap<ChunkKey, DownloadingChunkStatus>,
    num_downloaded: usize,

    // restore
    restorer: Restorer,
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
        let snapshot_epoch_id = current_sync_candidate
            .as_ref()
            .map_or(Default::default(), |c| c.get_snapshot_epoch_id().clone());
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
            pending_chunks: Default::default(),
            downloading_chunks: Default::default(),
            num_downloaded: 0,
            restorer: Restorer::new(snapshot_epoch_id),
            blame_vec_offset: 0,
        }
    }

    pub fn start_sync_for_candidate(
        &mut self, sync_candidate: SnapshotSyncCandidate,
        trusted_blame_block: H256, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        if self.current_sync_candidate.as_ref() == Some(&sync_candidate)
            && self.trusted_blame_block == trusted_blame_block
        {
            return;
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
        &self, io: &dyn NetworkContext,
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
        let peer = available_peers.choose(&mut thread_rng()).map(|p| *p);

        sync_handler.request_manager.request_with_delay(
            io,
            Box::new(request),
            peer,
            None,
        );
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "(status = {:?}, download = {}/{}/{})",
            self.status,
            self.pending_chunks.len(),
            self.downloading_chunks.len(),
            self.num_downloaded,
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

    pub fn trusted_blame_block(&self) -> H256 {
        self.inner.read().trusted_blame_block.clone()
    }

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
            match Self::validate_blame_states(
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
                    inner.restorer.snapshot_merkle_root =
                        snapshot_info.merkle_root;
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
            match Self::validate_epoch_receipts(
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
                &inner.restorer.snapshot_merkle_root,
                &request.start_chunk,
            ) {
                warn!("failed to validate snapshot manifest, error = {:?}", e);
                bail!(ErrorKind::InvalidSnapshotManifest(
                    "invalid chunk proofs in manifest".into(),
                ));
            }
        }

        let verifier = FullSyncVerifier::new(
            response.manifest.chunk_boundaries.len() + 1,
            response.manifest.chunk_boundaries.clone(),
            response.manifest.chunk_boundary_proofs.clone(),
            inner.restorer.snapshot_merkle_root,
            ctx.manager
                .graph
                .data_man
                .storage_manager
                .get_storage_manager()
                .get_snapshot_manager()
                .get_snapshot_db_manager(),
            &inner.restorer.snapshot_epoch_id,
        )?;
        inner.restorer.initialize_verifier(verifier);
        inner.pending_chunks.extend(response.manifest.into_chunks());

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
            "Snapshot manifest received, checkpoint = {:?}, elapsed = {:?}, chunks = {}",
            inner.current_sync_candidate,
            start_time.elapsed(),
            inner.pending_chunks.len(),
        );

        // update status
        inner.status = Status::DownloadingChunks(Instant::now());
        inner.receipt_blame_vec = response.receipt_blame_vec;
        inner.bloom_blame_vec = response.bloom_blame_vec;

        // request snapshot chunks from peers concurrently
        self.request_chunks(ctx, inner);

        debug!("sync state progress: {:?}", *inner);
        Ok(())
    }

    fn resync_manifest(&self, ctx: &Context, inner: &mut Inner) {
        inner.request_manifest(ctx.io, ctx.manager);
    }

    /// Request multiple chunks from random peers.
    fn request_chunks(&self, ctx: &Context, inner: &mut Inner) {
        if inner.current_sync_candidate.is_none() {
            // This may happen if called from `check_timeout`.
            return;
        }
        if inner.downloading_chunks.len() > self.config.max_downloading_chunks {
            // This should not happen.
            error!("downloading_chunks > max_downloading_chunks");
            return;
        }
        let chosen_peers = PeerFilter::new(msgid::GET_SNAPSHOT_CHUNK)
            .choose_from(inner.sync_candidate_manager.active_peers())
            .select_n(
                self.config.max_downloading_chunks
                    - inner.downloading_chunks.len(),
                &ctx.manager.syn,
            );
        for peer in chosen_peers {
            if self.request_chunk_from_peer(ctx, inner, &peer).is_none() {
                break;
            }
        }
    }

    fn request_chunk_from_peer(
        &self, ctx: &Context, inner: &mut Inner, peer: &NodeId,
    ) -> Option<ChunkKey> {
        let chunk_key = inner.pending_chunks.pop_front()?;
        assert!(inner
            .downloading_chunks
            .insert(
                chunk_key.clone(),
                DownloadingChunkStatus {
                    peer: *peer,
                    start_time: Instant::now(),
                }
            )
            .is_none());

        let request = SnapshotChunkRequest::new(
            inner
                .current_sync_candidate
                .clone()
                .expect("checked in request_chunks"),
            chunk_key.clone(),
        );

        ctx.manager.request_manager.request_with_delay(
            ctx.io,
            Box::new(request),
            Some(*peer),
            None,
        );

        Some(chunk_key)
    }

    pub fn handle_snapshot_chunk_response(
        &self, ctx: &Context, chunk_key: ChunkKey, chunk: Chunk,
    ) -> StorageResult<()> {
        let mut inner = self.inner.write();
        // status mismatch
        let download_start_time = match inner.status {
            Status::DownloadingChunks(t) => {
                debug!(
                    "Snapshot chunk received, checkpoint = {:?}, chunk = {:?}",
                    inner.current_sync_candidate, chunk_key
                );
                t
            }
            _ => {
                debug!("Snapshot chunk received, but mismatch with current status {:?}", inner.status);
                return Ok(());
            }
        };

        // There are two possible reasons:
        // 1. received a out-of-date snapshot chunk, e.g. new era started.
        // 2. Duplicated chunks received, and it has been processed.
        if inner.downloading_chunks.remove(&chunk_key).is_none() {
            info!("Snapshot chunk received, but not in downloading queue");
            // FIXME Handle out-of-date chunks
            inner
                .sync_candidate_manager
                .note_state_sync_failure(&ctx.node_id);
            self.request_chunks(ctx, &mut inner);
            return Ok(());
        }

        inner.num_downloaded += 1;
        inner.restorer.append(chunk_key, chunk);

        // continue to request remaining chunks
        self.request_chunks(ctx, &mut inner);

        // begin to restore if all chunks downloaded
        if inner.downloading_chunks.is_empty() {
            debug!(
                "Snapshot chunks are all downloaded in {:?}",
                download_start_time.elapsed()
            );

            let snapshot_info = inner.snapshot_info.clone();
            // start to restore and update status
            inner.restorer.finalize_restoration(
                ctx.manager.graph.data_man.storage_manager.clone(),
                snapshot_info,
            )?;
            inner.status = Status::Completed;
        }
        debug!("sync state progress: {:?}", *inner);
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

    fn validate_blame_states(
        ctx: &Context, snapshot_epoch_id: &H256, trusted_blame_block: &H256,
        state_root_vec: &Vec<StateRoot>, receipt_blame_vec: &Vec<H256>,
        bloom_blame_vec: &Vec<H256>,
    ) -> Option<(usize, StateRootWithAuxInfo, SnapshotInfo)>
    {
        let mut state_blame_vec = vec![];

        // these two header must exist in disk, it's safe to unwrap
        let snapshot_block_header = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(snapshot_epoch_id)
            .expect("block header must exist for snapshot to sync");
        let trusted_blame_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(trusted_blame_block)
            .expect("trusted_blame_block header must exist");

        // check snapshot position in `out_state_blame_vec`
        let offset = (trusted_blame_block.height()
            - (snapshot_block_header.height() + DEFERRED_STATE_EPOCH_COUNT))
            as usize;
        if offset >= state_root_vec.len() {
            warn!("validate_blame_states: not enough state_root");
            return None;
        }

        let min_vec_len = if snapshot_block_header.height() == 0 {
            trusted_blame_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - snapshot_block_header.height()
                + 1
        } else {
            trusted_blame_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - snapshot_block_header.height()
                + REWARD_EPOCH_COUNT
        };
        let mut trusted_blocks = Vec::new();
        let mut trusted_block_height = trusted_blame_block.height();
        let mut blame_count = trusted_blame_block.blame();
        let mut block_hash = trusted_blame_block.hash();
        let mut vec_len: usize = 0;
        trusted_blocks.push(trusted_blame_block);

        // verify the length of vector.
        loop {
            vec_len += 1;
            let block = ctx
                .manager
                .graph
                .data_man
                .block_header_by_hash(&block_hash)
                .expect("block header must exist");
            // We've jump to another trusted block.
            if block.height() + blame_count as u64 + 1 == trusted_block_height {
                trusted_block_height = block.height();
                blame_count = block.blame();
                trusted_blocks.push(block.clone());
            }
            if block.height() + blame_count as u64 == trusted_block_height
                && vec_len >= min_vec_len as usize
            {
                break;
            }
            block_hash = *block.parent_hash();
        }
        // verify the length of vector
        if vec_len != state_root_vec.len() {
            warn!(
                "wrong length of state_root_vec, expected {}, but {} found",
                vec_len,
                state_root_vec.len()
            );
            return None;
        }
        // Construct out_state_blame_vec.
        state_blame_vec.clear();
        for state_root in state_root_vec {
            state_blame_vec.push(state_root.compute_state_root_hash());
        }
        let mut slice_begin = 0;
        for trusted_block in trusted_blocks {
            let slice_end = slice_begin + trusted_block.blame() as usize + 1;
            let deferred_state_root = if trusted_block.blame() == 0 {
                state_blame_vec[slice_begin].clone()
            } else {
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    state_blame_vec[slice_begin..slice_end].to_vec(),
                )
            };
            let deferred_receipts_root = if trusted_block.blame() == 0 {
                receipt_blame_vec[slice_begin].clone()
            } else {
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    receipt_blame_vec[slice_begin..slice_end].to_vec(),
                )
            };
            let deferred_logs_bloom_hash = if trusted_block.blame() == 0 {
                bloom_blame_vec[slice_begin].clone()
            } else {
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    bloom_blame_vec[slice_begin..slice_end].to_vec(),
                )
            };
            // verify `deferred_state_root`, `deferred_receipts_root` and
            // `deferred_logs_bloom_hash`
            if deferred_state_root != *trusted_block.deferred_state_root()
                || deferred_receipts_root
                    != *trusted_block.deferred_receipts_root()
                || deferred_logs_bloom_hash
                    != *trusted_block.deferred_logs_bloom_hash()
            {
                warn!("root mismatch: (state_root, receipts_root, logs_bloom_hash) \
                should be ({:?} {:?} {:?}), get ({:?} {:?} {:?})",
                       trusted_block.deferred_state_root(),
                       trusted_block.deferred_receipts_root(),
                       trusted_block.deferred_logs_bloom_hash(),
                       deferred_state_root,
                       deferred_receipts_root,
                       deferred_logs_bloom_hash,
                );
                return None;
            }
            slice_begin = slice_end;
        }

        let (parent_snapshot_epoch, pivot_chain_parts) =
            ctx.manager.graph.data_man.get_parent_epochs_for(
                snapshot_epoch_id.clone(),
                ctx.manager.graph.data_man.get_snapshot_epoch_count() as u64,
            );

        let parent_snapshot_height = if parent_snapshot_epoch == NULL_EPOCH {
            0
        } else {
            ctx.manager
                .graph
                .data_man
                .block_header_by_hash(&parent_snapshot_epoch)
                .unwrap()
                .height()
        };
        let mut snapshot_state_root = state_root_vec[offset].clone();
        // This delta_root is the intermediate_delta_root of the new snapshot,
        // and this field will be used to fill new state_root in
        // get_state_trees_for_next_epoch
        snapshot_state_root.intermediate_delta_root =
            state_root_vec[offset].delta_root;

        Some((
            offset,
            StateRootWithAuxInfo {
                state_root: snapshot_state_root,
                aux_info: StateRootAuxInfo {
                    // FIXME: we should not commit the EpochExecutionCommitment
                    // FIXME: for the synced snapshot because it's fake.
                    // Should be parent of parent but we don't necessarily need
                    // to know. We put the
                    // parent_snapshot_merkle_root here.
                    snapshot_epoch_id: state_root_vec[offset - 1].snapshot_root,
                    // This field will not be used
                    delta_mpt_key_padding: StorageKey::delta_mpt_padding(
                        &state_root_vec[offset].snapshot_root,
                        &state_root_vec[offset].intermediate_delta_root,
                    ),
                    intermediate_epoch_id: parent_snapshot_epoch,
                    // We don't necessarily need to know because
                    // the execution of the next epoch shifts delta MPT.
                    maybe_intermediate_mpt_key_padding: None,
                },
            },
            SnapshotInfo {
                serve_one_step_sync: false,
                // We need the extra -1 to get a state root that points to the
                // snapshot we want.
                merkle_root: state_root_vec[offset
                    - ctx
                        .manager
                        .graph
                        .data_man
                        .get_snapshot_blame_plus_depth()]
                .snapshot_root,
                height: snapshot_block_header.height(),
                parent_snapshot_epoch_id: parent_snapshot_epoch,
                parent_snapshot_height,
                pivot_chain_parts,
            },
        ))
    }

    fn validate_epoch_receipts(
        ctx: &Context, blame_vec_offset: usize, snapshot_epoch_id: &EpochId,
        receipt_blame_vec: &Vec<H256>, bloom_blame_vec: &Vec<H256>,
        block_receipts: &Vec<BlockExecutionResult>,
    ) -> Option<Vec<(H256, H256, Arc<BlockReceipts>)>>
    {
        let mut epoch_hash = snapshot_epoch_id.clone();
        let checkpoint = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(snapshot_epoch_id)
            .expect("checkpoint header must exist");
        let epoch_receipts_count = if checkpoint.height() == 0 {
            1
        } else {
            REWARD_EPOCH_COUNT
        } as usize;
        let mut receipts_vec_offset = 0;
        let mut result = Vec::new();
        for idx in 0..epoch_receipts_count {
            let block_header = ctx
                .manager
                .graph
                .data_man
                .block_header_by_hash(&epoch_hash)
                .expect("block header must exist");
            let ordered_executable_epoch_blocks = ctx
                .manager
                .graph
                .consensus
                .get_block_hashes_by_epoch(EpochNumber::Number(
                    block_header.height(),
                ))
                .expect("ordered executable epoch blocks must exist");
            let mut epoch_receipts = Vec::new();
            for i in 0..ordered_executable_epoch_blocks.len() {
                if let Some(block_receipt) =
                    block_receipts.get(receipts_vec_offset + i)
                {
                    epoch_receipts.push(block_receipt.block_receipts.clone());
                } else {
                    // Invalid block_receipts vector length.
                    return None;
                }
            }
            let receipt_root = BlockHeaderBuilder::compute_block_receipts_root(
                &epoch_receipts,
            );
            let logs_bloom_hash =
                BlockHeaderBuilder::compute_block_logs_bloom_hash(
                    &epoch_receipts,
                );
            if receipt_blame_vec[blame_vec_offset + idx] != receipt_root {
                debug!(
                    "wrong receipt root, expected={:?}, now={:?}",
                    receipt_blame_vec[blame_vec_offset + idx],
                    receipt_root
                );
                return None;
            }
            if bloom_blame_vec[blame_vec_offset + idx] != logs_bloom_hash {
                debug!(
                    "wrong logs bloom hash, expected={:?}, now={:?}",
                    bloom_blame_vec[blame_vec_offset + idx],
                    logs_bloom_hash
                );
                return None;
            }
            for i in 0..ordered_executable_epoch_blocks.len() {
                result.push((
                    ordered_executable_epoch_blocks[i],
                    epoch_hash,
                    epoch_receipts[i].clone(),
                ));
            }
            receipts_vec_offset += ordered_executable_epoch_blocks.len();
            epoch_hash = *block_header.parent_hash();
        }
        if receipts_vec_offset == block_receipts.len() {
            Some(result)
        } else {
            None
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
        if self
            .inner
            .write()
            .sync_candidate_manager
            .on_peer_response(peer, supported_candidates, requested_candidates)
            .is_some()
        {
            self.inner.write().status = Status::StartCandidateSync;
        }
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
        self.check_timeout(
            &mut *inner,
            &Context {
                // node_id is not used here
                node_id: Default::default(),
                io,
                manager: sync_handler,
            },
        );
        if inner.sync_candidate_manager.is_inactive() {
            warn!("current sync candidate becomes inactive: {:?}", inner);
            inner.status = Status::Inactive;
            inner.current_sync_candidate = None;
            inner.trusted_blame_block = Default::default();
        }

        // If we moves into the next era, we should force state_sync to change
        // the candidates to states with in the new stable era. If the
        // era stays the same and a new snapshot becomes available, we
        // only change candidates if old candidates cannot to be synced,
        // so a state can be synced with one era time instead of only
        // one snapshot time
        if inner.sync_candidate_manager.current_era_genesis
            == current_era_genesis
        {
            // state sync started, so we only need to check if it's completed
            if inner.status == Status::Completed {
                return;
            } else if inner.sync_candidate_manager.active_peers().is_empty() {
                // Previous candidate sync failed. Start the next one.
                inner.status = Status::StartCandidateSync;
                inner.sync_candidate_manager.set_active_candidate();
            }

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
    }

    fn check_timeout(&self, inner: &mut Inner, ctx: &Context) {
        inner
            .sync_candidate_manager
            .check_timeout(&self.config.candidate_request_timeout);
        if let Some((manifest_start_time, peer)) =
            &inner.manifest_request_status
        {
            if manifest_start_time.elapsed()
                > self.config.manifest_request_timeout
            {
                inner.sync_candidate_manager.note_state_sync_failure(peer)
            }
        }
        let mut timeout_chunks = Vec::new();
        for (chunk_key, status) in &inner.downloading_chunks {
            if status.start_time.elapsed() > self.config.chunk_request_timeout {
                inner
                    .sync_candidate_manager
                    .note_state_sync_failure(&status.peer);
                timeout_chunks.push(chunk_key.clone());
            }
        }
        for timeout_key in timeout_chunks {
            inner.downloading_chunks.remove(&timeout_key);
            inner.pending_chunks.push_back(timeout_key);
        }
        self.request_chunks(ctx, inner);
    }
}

pub struct StateSyncConfiguration {
    pub max_downloading_chunks: usize,
    pub candidate_request_timeout: Duration,
    pub chunk_request_timeout: Duration,
    pub manifest_request_timeout: Duration,
}

struct DownloadingChunkStatus {
    peer: NodeId,
    start_time: Instant,
}
