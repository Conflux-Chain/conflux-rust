use crate::sync::{
    request_manager::RequestManager,
    state::{
        snapshot_chunk_request::SnapshotChunkRequest,
        snapshot_chunk_response::SnapshotChunkResponse,
        snapshot_manifest_request::SnapshotManifestRequest,
        snapshot_manifest_response::SnapshotManifestResponse, StateSync,
    },
    Error, ErrorKind, SynchronizationState,
};
use cfx_types::H256;
use keccak_hash::keccak;
use network::{NetworkContext, PeerId};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

const MAX_DOWNLOAD_PEERS: usize = 8;

enum Status {
    Idle,
    DownloadingManifest,
    DownloadingChunks,
}

pub struct SnapshotChunkSync {
    checkpoint: Option<H256>,
    sync: Arc<SynchronizationState>,
    status: Status,
    manifest: Option<SnapshotManifestResponse>,
    pending_chunks: VecDeque<H256>, // chunks waiting for download
}

impl StateSync for SnapshotChunkSync {
    fn start(
        &mut self, checkpoint: H256, io: &NetworkContext,
        request_manager: &RequestManager,
    )
    {
        if let Some(ref cur_checkpoint) = self.checkpoint {
            if cur_checkpoint == &checkpoint {
                return;
            }

            // todo cleanup current syncing with storage APIs
        }

        self.checkpoint = Some(checkpoint.clone());
        self.status = Status::DownloadingManifest;

        // start to request manifest with specified checkpoint
        let request = SnapshotManifestRequest::new(checkpoint);
        let peer = self.sync.get_random_peer(&HashSet::new());
        request_manager.send_general_request(io, peer, Box::new(request));
    }
}

impl SnapshotChunkSync {
    pub fn new(sync: Arc<SynchronizationState>) -> Self {
        SnapshotChunkSync {
            checkpoint: None,
            sync,
            status: Status::Idle,
            manifest: None,
            pending_chunks: VecDeque::new(),
        }
    }

    pub fn handle_snapshot_manifest_response(
        &mut self, io: &NetworkContext, peer: PeerId,
        response: SnapshotManifestResponse, request_manager: &RequestManager,
    ) -> Result<(), Error>
    {
        let message =
            request_manager.match_request(io, peer, response.request_id)?;

        // validate the responded manifest
        let request = message
            .downcast_general::<SnapshotManifestRequest>(io, request_manager)?;
        if request.checkpoint != response.checkpoint {
            return Err(ErrorKind::Invalid.into());
        }

        self.pending_chunks = VecDeque::from(response.chunk_hashes.clone());
        self.manifest = Some(response);
        self.status = Status::DownloadingChunks;

        self.request_snapshot_chunk(io, request_manager, None)
    }

    fn request_snapshot_chunk(
        &mut self, io: &NetworkContext, request_manager: &RequestManager,
        peer: Option<PeerId>,
    ) -> Result<(), Error>
    {
        let checkpoint = match &self.checkpoint {
            Some(cp) => cp.clone(),
            None => return Ok(()),
        };

        let peers = if let Some(peer) = peer {
            vec![peer]
        } else {
            // todo if peers not enough, start more thread when new peers
            // connected
            self.sync.get_random_peer_vec(MAX_DOWNLOAD_PEERS, |_| true)
        };

        for peer in peers {
            if let Some(chunk_hash) = self.pending_chunks.pop_front() {
                let request =
                    SnapshotChunkRequest::new(checkpoint.clone(), chunk_hash);
                request_manager.send_general_request(
                    io,
                    Some(peer),
                    Box::new(request),
                );
            } else {
                break;
            }
        }

        Ok(())
    }

    pub fn handle_snapshot_chunk_response(
        &mut self, io: &NetworkContext, peer: PeerId,
        response: SnapshotChunkResponse, request_manager: &RequestManager,
    ) -> Result<(), Error>
    {
        let message =
            request_manager.match_request(io, peer, response.request_id)?;

        // validate the responded chunk hash
        let request = message
            .downcast_general::<SnapshotChunkRequest>(io, request_manager)?;
        let responded_chunk_hash = keccak(response.chunk);
        if responded_chunk_hash != request.chunk_hash {
            return Err(ErrorKind::Invalid.into());
        }

        // todo restore the snapshot in storage
        // 1. restore async (e.g. via channel)
        // 2. when restore completed, verify the restored state root

        self.request_snapshot_chunk(io, request_manager, Some(peer))
    }
}
