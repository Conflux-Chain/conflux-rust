use crate::{
    storage::{
        storage_db::SnapshotInfo, FullSyncVerifier, Result as StorageResult,
        TrieProof,
    },
    sync::{
        message::{msgid, Context, SnapshotChunkRequest},
        state::{
            state_sync_chunk::restore::Restorer,
            storage::{Chunk, ChunkKey, RangedManifest, SnapshotSyncCandidate},
        },
        synchronization_state::PeerFilter,
    },
};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use network::node_table::NodeId;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::{Debug, Formatter},
    time::{Duration, Instant},
};

pub struct SnapshotChunkManager {
    pub snapshot_candidate: SnapshotSyncCandidate,
    snapshot_info: SnapshotInfo,

    active_peers: HashSet<NodeId>,
    pending_chunks: VecDeque<ChunkKey>,
    downloading_chunks: HashMap<ChunkKey, DownloadingChunkStatus>,
    num_downloaded: usize,
    config: SnapshotChunkConfig,

    restorer: Restorer,
}

impl SnapshotChunkManager {
    pub fn new_and_start(
        ctx: &Context, snapshot_candidate: SnapshotSyncCandidate,
        snapshot_info: SnapshotInfo, chunk_boundaries: Vec<Vec<u8>>,
        chunk_boundary_proofs: Vec<TrieProof>, active_peers: HashSet<NodeId>,
        config: SnapshotChunkConfig,
    ) -> StorageResult<Self>
    {
        let mut restorer = Restorer::new(
            *snapshot_candidate.get_snapshot_epoch_id(),
            snapshot_info.merkle_root,
        );

        let verifier = FullSyncVerifier::new(
            chunk_boundaries.len() + 1,
            chunk_boundaries.clone(),
            chunk_boundary_proofs.clone(),
            snapshot_info.merkle_root,
            ctx.manager
                .graph
                .data_man
                .storage_manager
                .get_storage_manager()
                .get_snapshot_manager()
                .get_snapshot_db_manager(),
            snapshot_info.get_snapshot_epoch_id(),
        )?;

        restorer.initialize_verifier(verifier);
        let chunks =
            RangedManifest::convert_boundaries_to_chunks(chunk_boundaries);
        let mut chunk_manager = Self {
            snapshot_candidate,
            snapshot_info,
            active_peers,
            pending_chunks: chunks.into(),
            downloading_chunks: Default::default(),
            num_downloaded: 0,
            config,
            restorer,
        };
        chunk_manager.request_chunks(ctx);
        Ok(chunk_manager)
    }

    /// Add a received chunk, and request new ones if needed.
    /// Return `Ok(true)` if all chunks have been received and the snapshot is
    /// reconstructed. Return `Ok(false)` if there are chunks missing.
    pub fn add_chunk(
        &mut self, ctx: &Context, chunk_key: ChunkKey, chunk: Chunk,
    ) -> StorageResult<bool> {
        // If a response is in `downloading_chunks`, we can process
        // it regardless of our current status, because we allow chunk requests
        // to be resumed if the snapshot to sync is unchanged.
        //
        // There are two possible reasons that a response is not in
        // `downloading_chunks`:
        // 1. received a out-of-date snapshot chunk, e.g. new era started.
        // 2. Chunks are received after timeout.
        if self.downloading_chunks.remove(&chunk_key).is_none() {
            info!("Snapshot chunk received, but not in downloading queue, progess is {:?}", self);
            return Ok(false);
        }

        self.num_downloaded += 1;

        if !self.restorer.append(chunk_key.clone(), chunk) {
            warn!("Receive invalid chunk during appending {:?}", chunk_key);
            self.pending_chunks.push_back(chunk_key);
            self.note_failure(&ctx.node_id)
        }

        // begin to restore if all chunks downloaded
        if self.downloading_chunks.is_empty() && self.pending_chunks.is_empty()
        {
            debug!("Snapshot chunks are all downloaded",);

            // start to restore and update status
            self.restorer.finalize_restoration(
                ctx.manager.graph.data_man.storage_manager.clone(),
                self.snapshot_info.clone(),
            )?;
            return Ok(true);
        }
        self.request_chunks(ctx);
        Ok(false)
    }

    fn request_chunk_from_peer(
        &mut self, ctx: &Context, peer: &NodeId,
    ) -> Option<ChunkKey> {
        let chunk_key = self.pending_chunks.pop_front()?;

        let replaced = self.downloading_chunks.insert(
            chunk_key.clone(),
            DownloadingChunkStatus {
                peer: *peer,
                start_time: Instant::now(),
            },
        );
        debug_assert!(replaced.is_none());

        let request = SnapshotChunkRequest::new(
            self.snapshot_candidate.clone(),
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

    /// Request multiple chunks from random peers.
    fn request_chunks(&mut self, ctx: &Context) {
        let chosen_peers = PeerFilter::new(msgid::GET_SNAPSHOT_CHUNK)
            .choose_from(&self.active_peers)
            .select_n(
                self.config.max_downloading_chunks
                    - self.downloading_chunks.len(),
                &ctx.manager.syn,
            );
        for peer in chosen_peers {
            if self.request_chunk_from_peer(ctx, &peer).is_none() {
                break;
            }
        }
    }

    /// Remove timeout chunks and request new chunks.
    pub fn check_timeout(&mut self, ctx: &Context) {
        let mut timeout_chunks = Vec::new();
        for (chunk_key, status) in &self.downloading_chunks {
            if status.start_time.elapsed() > self.config.chunk_request_timeout {
                self.active_peers.remove(&status.peer);
                timeout_chunks.push(chunk_key.clone());
            }
        }
        for timeout_key in timeout_chunks {
            self.downloading_chunks.remove(&timeout_key);
            self.pending_chunks.push_back(timeout_key);
        }
        self.request_chunks(ctx);
    }

    pub fn is_inactive(&self) -> bool { self.active_peers.is_empty() }

    pub fn set_active_peers(&mut self, new_active_peers: HashSet<NodeId>) {
        self.active_peers = new_active_peers;
    }

    pub fn on_peer_disconnected(&mut self, peer: &NodeId) {
        self.active_peers.remove(peer);
    }

    fn note_failure(&mut self, node_id: &NodeId) {
        self.active_peers.remove(node_id);
    }
}

impl Debug for SnapshotChunkManager {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "(download = {}/{}/{}, active_peers: {})",
            self.pending_chunks.len(),
            self.downloading_chunks.len(),
            self.num_downloaded,
            self.active_peers.len(),
        )
    }
}

#[derive(DeriveMallocSizeOf)]
struct DownloadingChunkStatus {
    peer: NodeId,
    start_time: Instant,
}

#[derive(DeriveMallocSizeOf)]
pub struct SnapshotChunkConfig {
    pub max_downloading_chunks: usize,
    pub chunk_request_timeout: Duration,
}
