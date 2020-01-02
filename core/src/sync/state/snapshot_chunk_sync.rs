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
        StateIndex, StateRootAuxInfo, StateRootWithAuxInfo,
    },
    sync::{
        message::{msgid, Context},
        state::{
            restore::Restorer,
            snapshot_chunk_request::SnapshotChunkRequest,
            snapshot_manifest_request::SnapshotManifestRequest,
            snapshot_manifest_response::SnapshotManifestResponse,
            storage::{Chunk, ChunkKey},
        },
        synchronization_state::PeerFilter,
        SynchronizationProtocolHandler,
    },
};
use cfx_types::H256;
use network::{NetworkContext, PeerId};
use parking_lot::RwLock;
use primitives::{
    BlockHeaderBuilder, MerkleHash, Receipt, StateRoot, StorageKey,
    MERKLE_NULL_NODE, NULL_EPOCH,
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

    /// State root verified by blame.
    true_state_root_by_blame_info: MerkleHash,
    /// Point to the corresponding entry to the snapshot in the blame vectors.
    blame_vec_offset: usize,
    receipt_blame_vec: Vec<H256>,
    bloom_blame_vec: Vec<H256>,
    epoch_receipts: Vec<(H256, H256, Arc<Vec<Receipt>>)>,
    snapshot_info: SnapshotInfo,

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
        self.true_state_root_by_blame_info = MERKLE_NULL_NODE;
        self.snapshot_info = SnapshotInfo::genesis_snapshot_info();
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
        // FIXME: start here.
        // consensus is available from sync_handler.
        let request = SnapshotManifestRequest::new(
            inner.checkpoint.clone(),
            inner.trusted_blame_block.clone(),
        );

        let peer = PeerFilter::new(msgid::GET_SNAPSHOT_MANIFEST)
            //            .with_cap(DynamicCapability::ServeCheckpoint(Some(
            //                inner.checkpoint,
            //            )))
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
                &response.state_root_vec,
                &response.receipt_blame_vec,
                &response.bloom_blame_vec,
            ) {
                Some((blame_vec_offset, _state, snapshot_info)) => {
                    let maybe_trusted_snapshot_blame_block = ctx
                        .manager
                        .graph
                        .consensus
                        .get_trusted_blame_block_for_snapshot(
                            &inner.checkpoint,
                        );
                    let snapshot_state_root =
                        match maybe_trusted_snapshot_blame_block {
                            Some(block) => {
                                let deferred_state_root = *ctx
                                    .manager
                                    .graph
                                    .data_man
                                    .block_header_by_hash(&block)
                                    .expect("trusted blame block should exist")
                                    .deferred_state_root();
                                if response
                                    .snapshot_state_root
                                    .compute_state_root_hash()
                                    != deferred_state_root
                                {
                                    warn!("ManifestResponse has invalid snapshot_root: should be {:?} in block {:?}", deferred_state_root, block);
                                    self.resync_manifest(ctx, &mut inner);
                                    return;
                                } else {
                                    response
                                        .snapshot_state_root
                                        .snapshot_root
                                        .clone()
                                }
                            }
                            None => {
                                // FIXME Ensure this does not happen
                                panic!("No blame block for synced snapshot!");
                            }
                        };
                    inner.true_state_root_by_blame_info = snapshot_state_root;
                    inner.restorer.snapshot_merkle_root = snapshot_state_root;
                    inner.blame_vec_offset = blame_vec_offset;
                    inner.snapshot_info = snapshot_info;
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
                &inner.true_state_root_by_blame_info,
                &request.start_chunk,
            ) {
                warn!("failed to validate snapshot manifest, error = {:?}", e);
                return;
            }
        }

        let verifier = match FullSyncVerifier::new(
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
        ) {
            Ok(verifier) => verifier,
            Err(e) => {
                warn!(
                    "Fail to create FullSyncVerifier from Manifest, err={:?}",
                    e
                );
                return;
            }
        };
        inner.restorer.initialize_verifier(verifier);
        inner.pending_chunks.extend(response.manifest.into_chunks());

        // FIXME Handle next_chunk

        //        let next_chunk = response.manifest.next_chunk();
        //        // continue to request remaining manifest if any
        //        if let Some(next_chunk) = next_chunk {
        //            let request =
        // SnapshotManifestRequest::new_with_start_chunk(
        // inner.checkpoint.clone(),                next_chunk,
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
            //            .with_cap(DynamicCapability::ServeCheckpoint(Some(
            //                inner.checkpoint,
            //            )))
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
    ) -> StorageResult<()> {
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
                return Ok(());
            }
        };

        // maybe received a out-of-date snapshot chunk, e.g. new era started
        if !inner.downloading_chunks.remove(&chunk_key) {
            info!("Snapshot chunk received, but not in downloading queue");
            return Ok(());
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
            inner.restorer.finalize_restoration(
                ctx.manager.graph.data_man.storage_manager.clone(),
                inner.snapshot_info.clone(),
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
        let mut deferred_block_hash = inner.trusted_blame_block;
        for _ in 0..DEFERRED_STATE_EPOCH_COUNT {
            deferred_block_hash = *sync_handler
                .graph
                .data_man
                .block_header_by_hash(&deferred_block_hash)
                .expect("All headers exist")
                .parent_hash();
        }
        // Delta height starts from 1. At the snapshot point the delta height
        // equals to the snapshot epoch count. When the delta height of
        // the next epoch is 1, the current epoch is a snapshot.
        let steps_to_snapshot = StateIndex::height_to_delta_height(
            sync_handler
                .graph
                .data_man
                .block_header_by_hash(&deferred_block_hash)
                .unwrap()
                .height()
                + 1,
            sync_handler.graph.data_man.get_snapshot_epoch_count(),
        ) - 1;
        let snapshot_epoch_id = sync_handler
            .graph
            .data_man
            .get_parent_epochs_for(
                deferred_block_hash,
                steps_to_snapshot as u64,
            )
            .0;
        let mut fake_state_root =
            StateRootWithAuxInfo::genesis(&MERKLE_NULL_NODE);
        fake_state_root.aux_info.snapshot_epoch_id = snapshot_epoch_id;
        fake_state_root.aux_info.intermediate_epoch_id = snapshot_epoch_id;
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
                    // point. FIXME: but these information
                    // won't be used.
                    fake_state_root.clone(),
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
            .expect("checkpoint header must exist");
        let trusted_blame_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(trusted_blame_block)
            .expect("trusted_blame_block header must exist");

        // check checkpoint position in `out_state_blame_vec`
        let offset = (trusted_blame_block.height()
            - (snapshot_block_header.height() + DEFERRED_STATE_EPOCH_COUNT))
            as usize;
        if offset >= state_root_vec.len() {
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
            debug!(
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

        Some((
            offset,
            StateRootWithAuxInfo {
                state_root: state_root_vec[offset].clone(),
                aux_info: StateRootAuxInfo {
                    snapshot_epoch_id: parent_snapshot_epoch,
                    delta_mpt_key_padding: StorageKey::delta_mpt_padding(
                        &state_root_vec[offset].snapshot_root,
                        &state_root_vec[offset].intermediate_delta_root,
                    ),
                    intermediate_epoch_id: *snapshot_epoch_id,
                    // We don't necessarily need to know.
                    maybe_intermediate_mpt_key_padding: None,
                },
            },
            SnapshotInfo {
                serve_one_step_sync: false,
                merkle_root: state_root_vec[offset].snapshot_root,
                height: snapshot_block_header.height(),
                parent_snapshot_epoch_id: parent_snapshot_epoch,
                parent_snapshot_height,
                pivot_chain_parts,
            },
        ))
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
