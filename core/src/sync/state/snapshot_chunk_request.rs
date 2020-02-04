// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, DynamicCapability, Handleable, KeyContainer},
    request_manager::{AsAny, Request},
    state::{
        snapshot_chunk_response::SnapshotChunkResponse,
        storage::{Chunk, ChunkKey},
    },
    Error, ProtocolConfiguration,
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct SnapshotChunkRequest {
    pub request_id: u64,
    pub checkpoint: H256,
    pub chunk_key: ChunkKey,
}

impl SnapshotChunkRequest {
    pub fn new(checkpoint: H256, chunk_key: ChunkKey) -> Self {
        SnapshotChunkRequest {
            request_id: 0,
            checkpoint,
            chunk_key,
        }
    }
}

impl Handleable for SnapshotChunkRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let chunk = match Chunk::load(
            &self.checkpoint,
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
        conf.blocks_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<dyn Request>> { None }

    fn required_capability(&self) -> Option<DynamicCapability> { None }
}
