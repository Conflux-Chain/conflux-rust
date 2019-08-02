// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{HasRequestId, Message, MsgId, RequestId},
    sync::{
        message::{
            msgid, Context, DynamicCapability, Handleable, KeyContainer,
        },
        request_manager::Request,
        state::snapshot_chunk_response::SnapshotChunkResponse,
        Error, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, collections::HashMap, time::Duration};

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct SnapshotChunkRequest {
    pub request_id: u64,
    pub checkpoint: H256,
    pub chunk_hash: H256,
}

impl SnapshotChunkRequest {
    pub fn new(checkpoint: H256, chunk_hash: H256) -> Self {
        SnapshotChunkRequest {
            request_id: 0,
            checkpoint,
            chunk_hash,
        }
    }
}

build_msg_impl! { SnapshotChunkRequest, msgid::GET_SNAPSHOT_CHUNK, "SnapshotChunkRequest" }
build_has_request_id_impl! { SnapshotChunkRequest }

impl Handleable for SnapshotChunkRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        // todo find chunk from storage APIs
        let kvs = HashMap::new();
        let response = SnapshotChunkResponse::new(self.request_id, kvs);
        ctx.send_response(&response)
    }
}

impl Request for SnapshotChunkRequest {
    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &mut KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &mut KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }

    fn required_capability(&self) -> Option<DynamicCapability> {
        Some(DynamicCapability::ServeCheckpoint(Some(
            self.checkpoint.clone(),
        )))
    }
}
