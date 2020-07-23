// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{
        GetMaybeRequestId, Message, MessageProtocolVersionBound, MsgId,
        RequestId, SetRequestId,
    },
    sync::{
        message::{
            msgid, Context, DynamicCapability, Handleable, KeyContainer,
            SnapshotChunkResponse,
        },
        request_manager::{AsAny, Request},
        state::storage::{Chunk, ChunkKey, SnapshotSyncCandidate},
        Error, ErrorKind, ProtocolConfiguration, SYNC_PROTO_V1, SYNC_PROTO_V2,
    },
};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use network::service::ProtocolVersion;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, Clone, RlpDecodable, RlpEncodable, DeriveMallocSizeOf)]
pub struct SnapshotChunkRequest {
    // request_id for SnapshotChunkRequest is independent from each other
    // because request_id is set per message when the request is sent.
    pub request_id: u64,
    pub snapshot_to_sync: SnapshotSyncCandidate,
    pub chunk_key: ChunkKey,
}

build_msg_with_request_id_impl! {
    SnapshotChunkRequest, msgid::GET_SNAPSHOT_CHUNK,
    "SnapshotChunkRequest", SYNC_PROTO_V1, SYNC_PROTO_V2
}

impl SnapshotChunkRequest {
    pub fn new(
        snapshot_sync_candidate: SnapshotSyncCandidate, chunk_key: ChunkKey,
    ) -> Self {
        SnapshotChunkRequest {
            request_id: 0,
            snapshot_to_sync: snapshot_sync_candidate,
            chunk_key,
        }
    }
}

impl Handleable for SnapshotChunkRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let snapshot_epoch_id = match &self.snapshot_to_sync {
            SnapshotSyncCandidate::FullSync {
                snapshot_epoch_id, ..
            } => snapshot_epoch_id,
            _ => bail!(ErrorKind::NotSupported(
                "OneStepSync/IncSync not yet implemented.".into()
            )),
        };
        let chunk = match Chunk::load(
            snapshot_epoch_id,
            &self.chunk_key,
            &ctx.manager.graph.data_man.storage_manager,
        ) {
            Ok(Some(chunk)) => chunk,
            _ => Chunk::default(),
        };

        ctx.send_response(&SnapshotChunkResponse {
            request_id: self.request_id,
            chunk,
        })
    }
}

impl AsAny for SnapshotChunkRequest {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Request for SnapshotChunkRequest {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.snapshot_chunk_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<dyn Request>> { None }

    fn required_capability(&self) -> Option<DynamicCapability> { None }
}
