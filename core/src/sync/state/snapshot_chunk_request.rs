// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable, KeyContainer, Message, MsgId},
    request_manager::Request,
    state::snapshot_chunk_response::SnapshotChunkResponse,
    Error, ProtocolConfiguration,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{any::Any, collections::HashMap, time::Duration};

#[derive(Debug, Clone)]
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

impl Handleable for SnapshotChunkRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        // todo find chunk from storage APIs
        let kvs = HashMap::new();
        let response = SnapshotChunkResponse::new(self.request_id, kvs);
        ctx.send_response(&response)
    }
}

impl Request for SnapshotChunkRequest {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id = request_id;
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &mut KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &mut KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }
}

impl Message for SnapshotChunkRequest {
    fn msg_id(&self) -> MsgId { MsgId::GET_SNAPSHOT_CHUNK }

    fn msg_name(&self) -> &'static str { "SnapshotChunkRequest" }
}

impl Encodable for SnapshotChunkRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.request_id)
            .append(&self.checkpoint)
            .append(&self.chunk_hash);
    }
}

impl Decodable for SnapshotChunkRequest {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(SnapshotChunkRequest {
            request_id: rlp.val_at(0)?,
            checkpoint: rlp.val_at(1)?,
            chunk_hash: rlp.val_at(2)?,
        })
    }
}
