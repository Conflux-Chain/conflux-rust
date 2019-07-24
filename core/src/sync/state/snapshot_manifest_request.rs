// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable, Message, MsgId},
    request_manager::Request as RequestMessage,
    state::snapshot_manifest_response::SnapshotManifestResponse,
    Error,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{any::Any, time::Duration};

#[derive(Debug, Clone)]
pub struct SnapshotManifestRequest {
    pub request_id: u64,
    pub checkpoint: H256,
}

impl SnapshotManifestRequest {
    pub fn new(checkpoint: H256) -> Self {
        SnapshotManifestRequest {
            request_id: 0,
            checkpoint,
        }
    }
}

impl Handleable for SnapshotManifestRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        // todo find manifest from storage APIs
        let response = SnapshotManifestResponse {
            request_id: self.request_id,
            checkpoint: self.checkpoint.clone(),
            state_root: H256::zero(),
            chunk_hashes: Vec::new(),
        };

        ctx.send_response(&response)
    }
}

impl RequestMessage for SnapshotManifestRequest {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id = request_id;
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    // todo configurable
    fn timeout(&self) -> Duration { Duration::from_secs(30) }

    fn on_removed(&self) {}

    fn preprocess(&self) -> Box<RequestMessage> {
        Box::new(SnapshotManifestRequest::new(self.checkpoint.clone()))
    }
}

impl Message for SnapshotManifestRequest {
    fn msg_id(&self) -> MsgId { MsgId::GET_SNAPSHOT_MANIFEST }
}

impl Encodable for SnapshotManifestRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.request_id)
            .append(&self.checkpoint);
    }
}

impl Decodable for SnapshotManifestRequest {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(SnapshotManifestRequest {
            request_id: rlp.val_at(0)?,
            checkpoint: rlp.val_at(1)?,
        })
    }
}
