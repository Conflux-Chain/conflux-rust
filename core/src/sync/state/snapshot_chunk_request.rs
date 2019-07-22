use crate::sync::{
    message::{Message, MsgId},
    msg_sender::send_message,
    request_manager::Request,
    state::snapshot_chunk_response::SnapshotChunkResponse,
    Error,
};
use cfx_types::H256;
use network::{NetworkContext, PeerId};
use priority_send_queue::SendQueuePriority;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{any::Any, time::Duration};

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

impl Request for SnapshotChunkRequest {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id = request_id;
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self) -> Duration { Duration::from_secs(120) }

    fn handle(self, io: &NetworkContext, peer: PeerId) -> Result<(), Error> {
        // todo find chunk from storage APIs
        let response = SnapshotChunkResponse {
            request_id: self.request_id,
            chunk: Vec::new(),
        };

        send_message(io, peer, &response, SendQueuePriority::High)?;

        Ok(())
    }

    fn on_removed(&self) {}

    fn preprocess(&self) -> Box<Request> {
        Box::new(SnapshotChunkRequest::new(
            self.checkpoint.clone(),
            self.chunk_hash.clone(),
        ))
    }
}

impl Message for SnapshotChunkRequest {
    fn msg_id(&self) -> MsgId { MsgId::GET_SNAPSHOT_CHUNK }
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
