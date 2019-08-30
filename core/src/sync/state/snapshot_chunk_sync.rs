// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::{Chunk, ChunkKey, RestoreProgress, Restorer},
    sync::{
        message::{Context, DynamicCapability},
        state::{
            snapshot_chunk_request::SnapshotChunkRequest,
            snapshot_manifest_request::SnapshotManifestRequest,
            snapshot_manifest_response::SnapshotManifestResponse,
        },
        SynchronizationProtocolHandler,
    },
};
use cfx_types::H256;
use network::{NetworkContext, PeerId};
use parking_lot::RwLock;
use primitives::BlockHeaderBuilder;
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
    true_state_root_by_blame_info: H256,

    // download
    pending_chunks: VecDeque<ChunkKey>,
    downloading_chunks: HashSet<ChunkKey>,
    num_downloaded: usize,

    // restore
    restorer: Restorer,
    restore_progress: RestoreProgress,
}

impl Inner {
    fn reset(&mut self, checkpoint: H256, trusted_blame_block: H256) {
        self.checkpoint = checkpoint;
        self.trusted_blame_block = trusted_blame_block;
        self.status = Status::DownloadingManifest(Instant::now());
        self.true_state_root_by_blame_info = H256::new();
        self.pending_chunks.clear();
        self.downloading_chunks.clear();
        self.num_downloaded = 0;
        self.restorer = Restorer::default();
        self.restore_progress = RestoreProgress::default();
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
            self.restore_progress,
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

        let peer = sync_handler.syn.get_random_peer_with_cap(Some(
            DynamicCapability::ServeCheckpoint(Some(inner.checkpoint.clone())),
        ));

        sync_handler.request_manager.request_with_delay(
            io,
            Box::new(request),
            peer,
            None,
        );
    }

    pub fn handle_snapshot_manifest_response(
        &self, ctx: &Context, response: SnapshotManifestResponse,
    ) {
        let mut inner = self.inner.write();

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
        if !response.state_blame_vec.is_empty() {
            match Self::validate_blame_states(
                ctx,
                &inner.checkpoint,
                &inner.trusted_blame_block,
                response.state_blame_vec,
            ) {
                Some(state) => inner.true_state_root_by_blame_info = state,
                None => {
                    warn!("failed to validate the blame state, re-sync manifest from other peer");
                    self.resync_manifest(ctx, &mut inner);
                    return;
                }
            }
        }

        inner.pending_chunks.extend(response.manifest.chunks());

        // continue to request remaining manifest if any
        if let Some(next_chunk) = response.manifest.next_chunk() {
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

        // request snapshot chunks from peers concurrently
        let peers = ctx.manager.syn.get_random_peers_satisfying(
            self.max_download_peers,
            |peer| {
                peer.capabilities
                    .contains(DynamicCapability::ServeCheckpoint(Some(
                        inner.checkpoint,
                    )))
            },
        );

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
        inner.restorer.append(&chunk_key, chunk);

        // continue to request remaining chunks
        self.request_chunk(ctx, &mut inner, ctx.peer);

        // begin to restore if all chunks downloaded
        if inner.downloading_chunks.is_empty() {
            debug!(
                "Snapshot chunks are all downloaded in {:?}",
                download_start_time.elapsed()
            );

            // start to restore and update status
            inner.restorer.start_to_restore();
            inner.status = Status::Restoring(Instant::now());
        }

        debug!("sync state progress: {:?}", *inner);
    }

    /// Update the progress of snapshot restoration.
    pub fn update_restore_progress(&self) {
        let mut inner = self.inner.write();

        let start_time = match inner.status {
            Status::Restoring(t) => t,
            _ => return,
        };

        inner.restore_progress = inner.restorer.progress();
        trace!(
            "Snapshot chunk restoration progress: {:?}",
            inner.restore_progress
        );
        if !inner.restore_progress.is_completed() {
            return;
        }

        info!(
            "Snapshot chunks restoration completed in {:?}",
            start_time.elapsed()
        );

        // verify the blame state
        let root = inner.restorer.restored_state_root();
        if root.compute_state_root_hash() == inner.true_state_root_by_blame_info
        {
            info!("Snapshot chunks restored successfully");
            inner.status = Status::Completed;
        } else {
            warn!("Failed to restore snapshot chunks, blame state mismatch");
            inner.status = Status::Invalid;
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
        state_blame_vec: Vec<H256>,
    ) -> Option<H256>
    {
        // these two header must exist in disk, it's safe to unwrap
        let checkpoint = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(checkpoint)
            .unwrap();
        let trusted_blame_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(trusted_blame_block)
            .unwrap();

        // check blame count correct
        if trusted_blame_block.blame() as usize + 1 != state_blame_vec.len() {
            return None;
        }
        // check checkpoint position in `state_blame_vec`
        let offset = trusted_blame_block.height() - checkpoint.height();
        if offset as usize >= state_blame_vec.len() {
            return None;
        }
        let deferred_state_root = if trusted_blame_block.blame() == 0 {
            state_blame_vec[0].clone()
        } else {
            BlockHeaderBuilder::compute_blame_state_root_vec_root(
                state_blame_vec.to_vec(),
            )
        };
        // check `deferred_state_root` is correct
        if deferred_state_root != *trusted_blame_block.deferred_state_root() {
            return None;
        }

        Some(state_blame_vec[offset as usize].clone())
    }
}
