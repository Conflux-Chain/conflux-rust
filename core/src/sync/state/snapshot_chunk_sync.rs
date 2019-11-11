// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockExecutionResult,
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        consensus_internal::REWARD_EPOCH_COUNT,
    },
    storage::state_manager::StateManager,
    sync::{
        message::{msgid, Context, DynamicCapability},
        state::{
            delta::{Chunk, ChunkKey},
            restore::Restorer,
            snapshot_chunk_request::SnapshotChunkRequest,
            snapshot_manifest_request::SnapshotManifestRequest,
            snapshot_manifest_response::SnapshotManifestResponse,
        },
        synchronization_state::PeerFilter,
        SynchronizationProtocolHandler,
    },
};
use cfx_types::H256;
use network::{NetworkContext, PeerId};
use parking_lot::RwLock;
use primitives::{
    BlockHeaderBuilder, Receipt, StateRoot, StateRootAuxInfo,
    StateRootWithAuxInfo,
};
use std::{
    collections::{HashSet, VecDeque},
    fmt::{Debug, Formatter, Result},
    sync::Arc,
    time::Instant,
};

#[derive(Copy, Clone, PartialEq)]
pub enum Status {
    Inactive,
    DownloadingManifest(Instant),
    DownloadingChunks(Instant),
    Restoring(Instant),
    Completed,
    Invalid,
}

impl Default for Status {
    fn default() -> Self { Status::Inactive }
}

impl Debug for Status {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let status = match self {
            Status::Inactive => "inactive".into(),
            Status::DownloadingManifest(t) => {
                format!("downloading manifest ({:?})", t.elapsed())
            }
            Status::DownloadingChunks(t) => {
                format!("downloading chunks ({:?})", t.elapsed())
            }
            Status::Restoring(t) => {
                format!("restoring chunks ({:?})", t.elapsed())
            }
            Status::Completed => "completed".into(),
            Status::Invalid => "invalid".into(),
        };

        write!(f, "{}", status)
    }
}

#[derive(Default)]
struct Inner {
    checkpoint: H256,
    trusted_blame_block: H256,
    status: Status,

    // blame state that used to verify restored state root
    true_state_root_by_blame_info: StateRoot,
    // Point to the corresponding entry to the checkpoint in the blame vectors.
    blame_vec_offset: usize,
    state_root_with_aux_info_vec: Vec<StateRootWithAuxInfo>,
    state_blame_vec: Vec<H256>,
    receipt_blame_vec: Vec<H256>,
    bloom_blame_vec: Vec<H256>,
    epoch_receipts: Vec<(H256, H256, Arc<Vec<Receipt>>)>,

    // download
    pending_chunks: VecDeque<ChunkKey>,
    downloading_chunks: HashSet<ChunkKey>,
    num_downloaded: usize,

    // restore
    restorer: Restorer,
}

impl Inner {
    fn reset(&mut self, checkpoint: H256, trusted_blame_block: H256) {
        self.checkpoint = checkpoint.clone();
        self.trusted_blame_block = trusted_blame_block;
        self.status = Status::DownloadingManifest(Instant::now());
        self.true_state_root_by_blame_info = StateRoot::default();
        self.state_blame_vec.clear();
        self.receipt_blame_vec.clear();
        self.bloom_blame_vec.clear();
        self.pending_chunks.clear();
        self.downloading_chunks.clear();
        self.num_downloaded = 0;
        self.restorer = Restorer::new_with_default_root_dir(checkpoint);
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "(status = {:?}, download = {}/{}/{}, restore progress = {:?})",
            self.status,
            self.pending_chunks.len(),
            self.downloading_chunks.len(),
            self.num_downloaded,
            self.restorer.progress(),
        )
    }
}

pub struct SnapshotChunkSync {
    inner: Arc<RwLock<Inner>>,
    max_download_peers: usize,
}

impl SnapshotChunkSync {
    pub fn new(max_download_peers: usize) -> Self {
        SnapshotChunkSync {
            inner: Default::default(),
            max_download_peers: if max_download_peers == 0 {
                1
            } else {
                max_download_peers
            },
        }
    }

    pub fn start(
        &self, checkpoint: H256, trusted_blame_block: H256,
        io: &dyn NetworkContext, sync_handler: &SynchronizationProtocolHandler,
    )
    {
        let mut inner = self.inner.write();

        if inner.checkpoint == checkpoint
            && inner.trusted_blame_block == trusted_blame_block
        {
            return;
        }

        info!("start to sync state, checkpoint = {:?}, trusted blame block = {:?}", checkpoint, trusted_blame_block);

        self.abort();

        inner.reset(checkpoint, trusted_blame_block);

        self.request_manifest(&inner, io, sync_handler);
    }

    fn abort(&self) {
        // todo cleanup current syncing with storage APIs
    }

    pub fn status(&self) -> Status { self.inner.read().status }

    pub fn checkpoint(&self) -> H256 { self.inner.read().checkpoint.clone() }

    /// request manifest from random peer
    fn request_manifest(
        &self, inner: &Inner, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        let request = SnapshotManifestRequest::new(
            inner.checkpoint.clone(),
            inner.trusted_blame_block.clone(),
        );

        let peer = PeerFilter::new(msgid::GET_SNAPSHOT_MANIFEST)
            .with_cap(DynamicCapability::ServeCheckpoint(Some(
                inner.checkpoint,
            )))
            .select(&sync_handler.syn);

        sync_handler.request_manager.request_with_delay(
            io,
            Box::new(request),
            peer,
            None,
        );
    }

    pub fn handle_snapshot_manifest_response(
        &self, ctx: &Context, response: SnapshotManifestResponse,
        request: &SnapshotManifestRequest,
    )
    {
        let mut inner = &mut *self.inner.write();

        // new era started
        if response.checkpoint != inner.checkpoint {
            info!(
                "Checkpoint changed and ignore the received snapshot manifest, new checkpoint = {:?}, requested checkpoint = {:?}",
                inner.checkpoint,
                response.checkpoint);
            return;
        }

        // status mismatch
        let start_time = match inner.status {
            Status::DownloadingManifest(start_time) => start_time,
            _ => {
                info!("Snapshot manifest received, but mismatch with current status {:?}", inner.status);
                return;
            }
        };

        // validate blame state if requested
        if request.is_initial_request() {
            match Self::validate_blame_states(
                ctx,
                &inner.checkpoint,
                &inner.trusted_blame_block,
                &mut inner.state_blame_vec,
                &mut inner.state_root_with_aux_info_vec,
                &response.state_root_vec,
                &response.receipt_blame_vec,
                &response.bloom_blame_vec,
            ) {
                Some((blame_vec_offset, state)) => {
                    inner.true_state_root_by_blame_info = state;
                    inner.blame_vec_offset = blame_vec_offset;
                }
                None => {
                    warn!("failed to validate the blame state, re-sync manifest from other peer");
                    self.resync_manifest(ctx, &mut inner);
                    return;
                }
            }
            match Self::validate_epoch_receipts(
                ctx,
                inner.blame_vec_offset,
                &inner.checkpoint,
                &response.receipt_blame_vec,
                &response.bloom_blame_vec,
                &response.block_receipts,
            ) {
                Some(epoch_receipts) => inner.epoch_receipts = epoch_receipts,
                None => {
                    warn!("failed to validate the epoch receipts, re-sync manifest from other peer");
                    self.resync_manifest(ctx, &mut inner);
                    return;
                }
            }

            // Check proofs for keys.
            if let Err(e) = response.manifest.validate(
                &inner.true_state_root_by_blame_info.snapshot_root,
                &request.start_chunk,
            ) {
                warn!("failed to validate snapshot manifest, error = {:?}", e);
                return;
            }
        }

        let next_chunk = response.manifest.next_chunk();
        inner.pending_chunks.extend(response.manifest.into_chunks());

        // continue to request remaining manifest if any
        if let Some(next_chunk) = next_chunk {
            let request = SnapshotManifestRequest::new_with_start_chunk(
                inner.checkpoint.clone(),
                next_chunk,
            );
            ctx.manager.request_manager.request_with_delay(
                ctx.io,
                Box::new(request),
                Some(ctx.peer),
                None,
            );
            return;
        }

        // todo validate the integrity of manifest, and re-sync it if failed

        info!(
            "Snapshot manifest received, checkpoint = {:?}, elapsed = {:?}, chunks = {}",
            inner.checkpoint,
            start_time.elapsed(),
            inner.pending_chunks.len(),
        );

        // update status
        inner.status = Status::DownloadingChunks(Instant::now());
        inner.receipt_blame_vec = response.receipt_blame_vec;
        inner.bloom_blame_vec = response.bloom_blame_vec;

        // request snapshot chunks from peers concurrently
        let peers = PeerFilter::new(msgid::GET_SNAPSHOT_CHUNK)
            .with_cap(DynamicCapability::ServeCheckpoint(Some(
                inner.checkpoint,
            )))
            .select_n(self.max_download_peers, &ctx.manager.syn);

        for peer in peers {
            if self.request_chunk(ctx, &mut inner, peer).is_none() {
                break;
            }
        }

        debug!("sync state progress: {:?}", *inner);
    }

    fn resync_manifest(&self, ctx: &Context, inner: &mut Inner) {
        let checkpoint = inner.checkpoint.clone();
        let trusted_blame_block = inner.trusted_blame_block.clone();
        inner.reset(checkpoint, trusted_blame_block);
        self.request_manifest(&inner, ctx.io, ctx.manager);
    }

    fn request_chunk(
        &self, ctx: &Context, inner: &mut Inner, peer: PeerId,
    ) -> Option<ChunkKey> {
        let chunk_key = inner.pending_chunks.pop_front()?;
        assert!(inner.downloading_chunks.insert(chunk_key.clone()));

        let request = SnapshotChunkRequest::new(
            inner.checkpoint.clone(),
            chunk_key.clone(),
        );

        ctx.manager.request_manager.request_with_delay(
            ctx.io,
            Box::new(request),
            Some(peer),
            None,
        );

        Some(chunk_key)
    }

    pub fn handle_snapshot_chunk_response(
        &self, ctx: &Context, chunk_key: ChunkKey, chunk: Chunk,
    ) {
        let mut inner = self.inner.write();

        // status mismatch
        let download_start_time = match inner.status {
            Status::DownloadingChunks(t) => {
                debug!(
                    "Snapshot chunk received, checkpoint = {:?}, chunk = {:?}",
                    inner.checkpoint, chunk_key
                );
                t
            }
            _ => {
                debug!("Snapshot chunk received, but mismatch with current status {:?}", inner.status);
                return;
            }
        };

        // maybe received a out-of-date snapshot chunk, e.g. new era started
        if !inner.downloading_chunks.remove(&chunk_key) {
            info!("Snapshot chunk received, but not in downloading queue");
            return;
        }

        inner.num_downloaded += 1;
        inner.restorer.append(chunk_key, chunk);

        // continue to request remaining chunks
        self.request_chunk(ctx, &mut inner, ctx.peer);

        // begin to restore if all chunks downloaded
        if inner.downloading_chunks.is_empty() {
            debug!(
                "Snapshot chunks are all downloaded in {:?}",
                download_start_time.elapsed()
            );

            // start to restore and update status
            inner.restorer.start_to_restore(
                ctx.manager.graph.data_man.storage_manager.clone(),
            );
            inner.status = Status::Restoring(Instant::now());
        }

        debug!("sync state progress: {:?}", *inner);
    }

    /// Update the progress of snapshot restoration.
    pub fn update_restore_progress(&self, state_manager: Arc<StateManager>) {
        let mut inner = self.inner.write();

        let start_time = match inner.status {
            Status::Restoring(t) => t,
            _ => return,
        };

        let progress = inner.restorer.progress();
        trace!("Snapshot chunk restoration progress: {:?}", progress);
        if !progress.is_completed() {
            return;
        }

        info!(
            "Snapshot chunks restoration completed in {:?}",
            start_time.elapsed()
        );

        // verify the blame state
        let root = inner.restorer.restored_state_root(state_manager);
        if root == inner.true_state_root_by_blame_info {
            info!("Snapshot chunks restored successfully");
            inner.status = Status::Completed;
        } else {
            warn!(
                "Failed to restore snapshot chunks, blame state mismatch,\
                 restored = {:?}, expected = {:?}",
                root, inner.true_state_root_by_blame_info
            );
            inner.status = Status::Invalid;
        }
    }

    pub fn restore_execution_state(
        &self, sync_handler: &SynchronizationProtocolHandler,
    ) {
        let inner = self.inner.read();
        let mut hashes = Vec::new();
        let mut deferred_block_hash = inner.trusted_blame_block;
        for _ in 0..DEFERRED_STATE_EPOCH_COUNT {
            deferred_block_hash = *sync_handler
                .graph
                .data_man
                .block_header_by_hash(&deferred_block_hash)
                .expect("All headers exist")
                .parent_hash();
        }
        for i in 0..(inner.blame_vec_offset + REWARD_EPOCH_COUNT as usize) {
            hashes.push(deferred_block_hash);
            info!(
                "insert_epoch_execution_commitments for block hash {:?}",
                &deferred_block_hash
            );
            sync_handler
                .graph
                .data_man
                .insert_epoch_execution_commitments(
                    deferred_block_hash,
                    inner.state_root_with_aux_info_vec[i].clone(),
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
            sync_handler.graph.data_man.insert_block_results(
                *block_hash,
                *epoch_hash,
                receipts.clone(),
                true, /* persistent */
            );
        }
    }

    pub fn on_checkpoint_served(&self, ctx: &Context, checkpoint: &H256) {
        let mut inner = self.inner.write();

        if !inner.downloading_chunks.is_empty()
            && inner.downloading_chunks.len() < self.max_download_peers
            && checkpoint == &inner.checkpoint
        {
            self.request_chunk(ctx, &mut inner, ctx.peer);
        }
    }

    fn validate_blame_states(
        ctx: &Context, checkpoint: &H256, trusted_blame_block: &H256,
        out_state_blame_vec: &mut Vec<H256>,
        out_state_root_with_aux_info_vec: &mut Vec<StateRootWithAuxInfo>,
        state_root_vec: &Vec<StateRoot>, receipt_blame_vec: &Vec<H256>,
        bloom_blame_vec: &Vec<H256>,
    ) -> Option<(usize, StateRoot)>
    {
        // these two header must exist in disk, it's safe to unwrap
        let checkpoint = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(checkpoint)
            .expect("checkpoint header must exist");
        let trusted_blame_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(trusted_blame_block)
            .expect("trusted_blame_block header must exist");

        // check checkpoint position in `out_state_blame_vec`
        let offset = (trusted_blame_block.height()
            - (checkpoint.height() + DEFERRED_STATE_EPOCH_COUNT))
            as usize;
        if offset >= state_root_vec.len() {
            return None;
        }

        let min_vec_len = if checkpoint.height() == 0 {
            trusted_blame_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - checkpoint.height()
                + 1
        } else {
            trusted_blame_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - checkpoint.height()
                + REWARD_EPOCH_COUNT
        };
        let mut trusted_blocks = Vec::new();
        let mut trusted_block_height = trusted_blame_block.height();
        let mut blame_count = trusted_blame_block.blame();
        let mut block_hash = trusted_blame_block.hash();
        let mut vec_len: usize = 0;
        trusted_blocks.push(trusted_blame_block);

        // Construct out_state_root_with_aux_info_vec.
        out_state_root_with_aux_info_vec.clear();
        for state_root in state_root_vec {
            out_state_root_with_aux_info_vec.push(StateRootWithAuxInfo {
                state_root: state_root.clone(),
                aux_info: StateRootAuxInfo::default(),
            });
        }
        // FIXME: build StateRootAuxInfo till the snapshot.

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
            debug!(
                "wrong length of state_root_vec, expected {}, but {} found",
                vec_len,
                state_root_vec.len()
            );
            return None;
        }
        // Construct out_state_blame_vec.
        out_state_blame_vec.clear();
        for state_root in state_root_vec {
            out_state_blame_vec.push(state_root.compute_state_root_hash());
        }
        let mut slice_begin = 0;
        for trusted_block in trusted_blocks {
            let slice_end = slice_begin + trusted_block.blame() as usize + 1;
            // FIXME: verify state_root_with_aux_info ..
            let deferred_state_root = if trusted_block.blame() == 0 {
                out_state_blame_vec[slice_begin].clone()
            } else {
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    out_state_blame_vec[slice_begin..slice_end].to_vec(),
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
                return None;
            }
            slice_begin = slice_end;
        }

        Some((offset, state_root_vec[offset].clone()))
    }

    fn validate_epoch_receipts(
        ctx: &Context, blame_vec_offset: usize, checkpoint: &H256,
        receipt_blame_vec: &Vec<H256>, bloom_blame_vec: &Vec<H256>,
        block_receipts: &Vec<BlockExecutionResult>,
    ) -> Option<Vec<(H256, H256, Arc<Vec<Receipt>>)>>
    {
        let mut epoch_hash = checkpoint.clone();
        let checkpoint = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(checkpoint)
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
                .inner
                .read()
                .block_hashes_by_epoch(block_header.height())
                .expect("ordered executable epoch blocks must exist");
            let mut epoch_receipts = Vec::new();
            for i in 0..ordered_executable_epoch_blocks.len() {
                epoch_receipts.push(Arc::new(
                    block_receipts[receipts_vec_offset + i]
                        .receipts
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>(),
                ));
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
}
