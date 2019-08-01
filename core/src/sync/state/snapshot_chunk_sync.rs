// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{CheckpointBlameStateRequest, Context, DynamicCapability},
    state::{
        snapshot_chunk_request::SnapshotChunkRequest,
        snapshot_manifest_request::SnapshotManifestRequest,
        snapshot_manifest_response::SnapshotManifestResponse, StateSync,
    },
    SynchronizationProtocolHandler,
};
use cfx_bytes::Bytes;
use cfx_types::H256;
use network::{NetworkContext, PeerId};
use parking_lot::RwLock;
use primitives::BlockHeaderBuilder;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::{Debug, Formatter, Result},
    time::Instant,
};

#[derive(Copy, Clone)]
pub enum Status {
    Inactive,
    DownloadingManifest(Instant),
    DownloadingChunks(Instant),
    Completed(H256),
    CheckingBlameState,
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
            Status::Completed(checkpoint) => {
                format!("completed ({:?})", checkpoint)
            }
            Status::CheckingBlameState => "checking blame state".into(),
            Status::Invalid => "invalid".into(),
        };

        write!(f, "{}", status)
    }
}

#[derive(Default)]
struct Inner {
    checkpoint: H256,
    trusted_blame_block: Option<H256>,
    status: Status,
    pending_chunks: VecDeque<H256>,
    downloading_chunks: HashSet<H256>,
    restoring_chunks: HashSet<H256>,
    restored_chunks: HashSet<H256>,
}

impl Inner {
    fn reset(&mut self, checkpoint: H256) {
        self.checkpoint = checkpoint;
        self.trusted_blame_block = None;
        self.status = Status::DownloadingManifest(Instant::now());
        self.pending_chunks.clear();
        self.downloading_chunks.clear();
        self.restoring_chunks.clear();
        self.restored_chunks.clear();
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "(status = {:?}, pending = {}, downloading = {}, restoring = {}, restored = {})",
            self.status,
            self.pending_chunks.len(),
            self.downloading_chunks.len(),
            self.restoring_chunks.len(),
            self.restored_chunks.len(),
        )
    }
}

pub struct SnapshotChunkSync {
    inner: RwLock<Inner>,
    max_download_peers: usize,
}

impl StateSync for SnapshotChunkSync {
    fn start(
        &self, checkpoint: H256, io: &NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
    )
    {
        let mut inner = self.inner.write();

        if inner.checkpoint == checkpoint {
            return;
        }

        self.abort();

        inner.reset(checkpoint.clone());

        // start to request manifest with specified checkpoint
        let request = SnapshotManifestRequest::new(checkpoint);
        let peer = sync_handler.syn.get_random_peer_satisfying(|peer| {
            peer.capabilities
                .contains(DynamicCapability::ServeCheckpoint(Some(
                    inner.checkpoint,
                )))
        });

        sync_handler.request_manager.request_with_delay(
            io,
            Box::new(request),
            peer,
            None,
        );
    }
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

    fn abort(&self) {
        // todo cleanup current syncing with storage APIs
    }

    pub fn status(&self) -> Status { self.inner.read().status }

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
        match inner.status {
            Status::DownloadingManifest(start_time) => {
                info!(
                    "Snapshot manifest received, checkpoint = {:?}, elapsed = {:?}, chunks = {}",
                    inner.checkpoint,
                    start_time.elapsed(),
                    response.chunk_hashes.len(),
                );
            }
            _ => {
                info!("Snapshot manifest received, but mismatch with current status {:?}", inner.status);
                return;
            }
        }

        // update status
        inner
            .pending_chunks
            .extend(response.chunk_hashes.into_iter());
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

    fn request_chunk(
        &self, ctx: &Context, inner: &mut Inner, peer: PeerId,
    ) -> Option<H256> {
        let chunk_hash = inner.pending_chunks.pop_front()?;
        assert!(inner.downloading_chunks.insert(chunk_hash));

        let request = SnapshotChunkRequest::new(
            inner.checkpoint.clone(),
            chunk_hash.clone(),
        );

        ctx.manager.request_manager.request_with_delay(
            ctx.io,
            Box::new(request),
            Some(peer),
            None,
        );

        Some(chunk_hash)
    }

    pub fn handle_snapshot_chunk_response(
        &self, ctx: &Context, chunk: H256, _kvs: HashMap<H256, Bytes>,
    ) {
        let mut inner = self.inner.write();

        // status mismatch
        let download_start_time: Instant;
        match inner.status {
            Status::DownloadingChunks(t) => {
                download_start_time = t;
                debug!(
                    "Snapshot chunk received, checkpoint = {:?}, chunk = {:?}",
                    inner.checkpoint, chunk
                );
            }
            _ => {
                debug!("Snapshot chunk received, but mismatch with current status {:?}", inner.status);
                return;
            }
        }

        // maybe received a out-of-date snapshot chunk, e.g. new era started
        if !inner.downloading_chunks.remove(&chunk) {
            debug!("Snapshot chunk received, but not in downloading queue");
            return;
        }

        assert_eq!(inner.restoring_chunks.contains(&chunk), false);
        assert_eq!(inner.restored_chunks.contains(&chunk), false);

        // todo restore the snapshot in storage
        // 1. restore async (e.g. via channel, write to disk first)
        // 2. when restore completed, verify the restored state root
        inner.restoring_chunks.insert(chunk);

        // continue to request remaining chunks
        self.request_chunk(ctx, &mut inner, ctx.peer);

        if inner.downloading_chunks.is_empty() {
            debug!(
                "Snapshot chunks are all downloaded in {:?}",
                download_start_time.elapsed()
            );
            // TODO: these code should be called after restore completed
            // FIXME: we may not find a trusted_blame_block
            inner.status = Status::CheckingBlameState;
            inner.trusted_blame_block =
                ctx.manager.graph.consensus.get_trusted_blame_block();
            self.request_checkpoint_blame_state(ctx, &mut inner);
        }

        debug!("sync state progress: {:?}", *inner);
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

    fn request_checkpoint_blame_state(&self, ctx: &Context, inner: &mut Inner) {
        // we don't find a trusted_blame_block, refuse to send a request and
        // wait for next era
        if inner.trusted_blame_block.is_none() {
            return;
        }

        let request = CheckpointBlameStateRequest::new(
            inner.trusted_blame_block.unwrap(),
        );

        let peer = ctx.manager.syn.get_random_peer_satisfying(|peer| {
            peer.capabilities
                .contains(DynamicCapability::ServeCheckpoint(Some(
                    inner.checkpoint,
                )))
        });

        ctx.manager.request_manager.request_with_delay(
            ctx.io,
            Box::new(request),
            peer,
            None,
        );
    }

    pub fn handle_checkpoint_blame_state_response(
        &self, ctx: &Context, state_blame_vec: &Vec<H256>,
    ) {
        let mut inner = self.inner.write();

        // match status
        match inner.status {
            Status::CheckingBlameState => {
                info!(
                    "state_blame_vec received, checkpoint = {:?} trusted_blame_block = {:?}",
                    inner.checkpoint,
                    inner.trusted_blame_block,
                );
            }
            _ => {
                info!("state_blame_vec received, but mismatch with current status {:?}", inner.status);
                return;
            }
        }

        // empty vector, consider that peer does not have the block information,
        // random peek another peer to send the request again
        // TODO: handle the case when checkpoint changes
        if state_blame_vec.is_empty() {
            self.request_checkpoint_blame_state(ctx, &mut inner);
            return;
        }
        // these two header must exist in disk, it's safe to unwrap
        let checkpoint = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(&inner.checkpoint)
            .unwrap();
        let trusted_blame_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(&inner.trusted_blame_block.unwrap())
            .unwrap();

        // check blame count correct
        if trusted_blame_block.blame() as usize + 1 != state_blame_vec.len() {
            inner.status = Status::Invalid;
            return;
        }
        // check checkpoint position in `state_blame_vec`
        let offset = trusted_blame_block.height() - checkpoint.height();
        if offset as usize >= state_blame_vec.len() {
            inner.status = Status::Invalid;
            return;
        }
        let deferred_state_root = if trusted_blame_block.blame() == 0 {
            state_blame_vec[0]
        } else {
            BlockHeaderBuilder::compute_blame_state_root_vec_root(
                state_blame_vec.to_vec(),
            )
        };
        // check `deferred_state_root` is correct
        if deferred_state_root != *trusted_blame_block.deferred_state_root() {
            inner.status = Status::Invalid;
            return;
        }
        // TODO: check state_blame_vec[offset] equals to recovered checkpoint
        // state_root
        inner.status = Status::Completed(inner.checkpoint);
    }
}
