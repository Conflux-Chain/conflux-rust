use crate::sync::{
    message::{Message, MsgId},
    msg_sender::send_message,
    request_manager::Request,
    state::snapshot_manifest_response::SnapshotManifestResponse,
    Error,
};
use cfx_types::H256;
use network::{NetworkContext, PeerId};
use priority_send_queue::SendQueuePriority;
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

impl Request for SnapshotManifestRequest {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id = request_id;
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    // todo configurable
    fn timeout(&self) -> Duration { Duration::from_secs(30) }

    fn handle(self, io: &NetworkContext, peer: PeerId) -> Result<(), Error> {
        // todo find manifest from storage APIs
        let response = SnapshotManifestResponse {
            request_id: self.request_id,
            checkpoint: self.checkpoint,
            state_root: H256::zero(),
            chunk_hashes: Vec::new(),
        };

        send_message(io, peer, &response, SendQueuePriority::High)?;

        Ok(())
    }

    fn on_removed(&self) {}

    fn preprocess(&self) -> Box<Request> {
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
