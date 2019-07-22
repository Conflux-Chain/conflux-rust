use cfx_bytes::Bytes;
use message::{Message, MsgId};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Debug)]
pub struct SnapshotChunkResponse {
    pub request_id: u64,
    pub chunk: Bytes,
}

impl Message for SnapshotChunkResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_SNAPSHOT_CHUNK_RESPONSE }
}

impl Encodable for SnapshotChunkResponse {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.request_id)
            .append_list(&self.chunk);
    }
}

impl Decodable for SnapshotChunkResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(SnapshotChunkResponse {
            request_id: rlp.val_at(0)?,
            chunk: rlp.list_at(1)?,
        })
    }
}
