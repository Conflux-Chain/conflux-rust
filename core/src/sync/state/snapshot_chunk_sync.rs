// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::Context,
    state::{
        snapshot_chunk_request::SnapshotChunkRequest,
        snapshot_chunk_response::SnapshotChunkResponse,
        snapshot_manifest_request::SnapshotManifestRequest,
        snapshot_manifest_response::SnapshotManifestResponse, StateSync,
    },
    Error, ErrorKind, SynchronizationProtocolHandler,
};
use cfx_types::H256;
use keccak_hash::keccak;
use network::NetworkContext;
use parking_lot::RwLock;
use std::collections::{HashSet, VecDeque};

const MAX_DOWNLOAD_PEERS: usize = 8;

enum Status {
    Inactive,
    DownloadingManifest,
    DownloadingChunks,
    Restoring,
    Completed,
}

impl Default for Status {
    fn default() -> Self { Status::Inactive }
}

#[derive(Default)]
struct Inner {
    checkpoint: H256,
    status: Status,
    manifest: Option<SnapshotManifestResponse>,
    pending_chunks: VecDeque<H256>,
}

#[derive(Default)]
pub struct SnapshotChunkSync {
    inner: RwLock<Inner>,
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

        inner.checkpoint = checkpoint.clone();
        inner.status = Status::DownloadingManifest;

        // start to request manifest with specified checkpoint
        let request = SnapshotManifestRequest::new(checkpoint);
        let peer = sync_handler.syn.get_random_peer(&HashSet::new());

        sync_handler.request_manager.request_with_delay(
            io,
            Box::new(request),
            peer,
            None,
        );
    }
}

impl SnapshotChunkSync {
    fn abort(&self) {
        // todo cleanup current syncing with storage APIs
    }

    pub fn handle_snapshot_manifest_response(
        &self, ctx: &Context, response: SnapshotManifestResponse,
    ) -> Result<(), Error> {
        let message = ctx.match_request(response.request_id)?;
        let request = message.downcast_ref::<SnapshotManifestRequest>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;

        // validate the responded manifest
        if request.checkpoint != response.checkpoint {
            ctx.manager
                .request_manager
                .remove_mismatch_request(ctx.io, &message);
            return Err(ErrorKind::Invalid.into());
        }

        // todo validate the responded: state root, checkpoint and current
        // status

        let mut inner = self.inner.write();

        inner.pending_chunks = VecDeque::from(response.chunk_hashes.clone());
        inner.manifest = Some(response);
        inner.status = Status::DownloadingChunks;

        // todo if peers not enough, start more when new peer connected
        let peers = ctx
            .manager
            .syn
            .get_random_peer_vec(MAX_DOWNLOAD_PEERS, |_| true);

        for peer in peers {
            if let Some(chunk_hash) = inner.pending_chunks.pop_front() {
                let request =
                    SnapshotChunkRequest::new(inner.checkpoint, chunk_hash);
                ctx.manager.request_manager.request_with_delay(
                    ctx.io,
                    Box::new(request),
                    Some(peer),
                    None,
                );
            } else {
                break;
            }
        }

        Ok(())
    }

    pub fn handle_snapshot_chunk_response(
        &self, ctx: &Context, response: SnapshotChunkResponse,
    ) -> Result<(), Error> {
        let message = ctx.match_request(response.request_id)?;
        let request = message.downcast_ref::<SnapshotChunkRequest>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;

        // validate the responded chunk hash
        let responded_chunk_hash = keccak(response.chunk);
        if responded_chunk_hash != request.chunk_hash {
            ctx.manager
                .request_manager
                .remove_mismatch_request(ctx.io, &message);
            return Err(ErrorKind::Invalid.into());
        }

        // todo restore the snapshot in storage
        // 1. restore async (e.g. via channel)
        // 2. when restore completed, verify the restored state root

        let mut inner = self.inner.write();

        match inner.pending_chunks.pop_front() {
            Some(chunk_hash) => {
                let request = SnapshotChunkRequest::new(
                    inner.checkpoint.clone(),
                    chunk_hash,
                );
                ctx.manager.request_manager.request_with_delay(
                    ctx.io,
                    Box::new(request),
                    Some(ctx.peer),
                    None,
                );
            }
            None => {
                inner.status = Status::Restoring;
            }
        }

        Ok(())
    }
}
