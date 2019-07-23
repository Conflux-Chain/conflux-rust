// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::{Message, MsgId};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Debug)]
pub struct SnapshotManifestResponse {
    pub request_id: u64,
    pub checkpoint: H256,
    pub state_root: H256,
    pub chunk_hashes: Vec<H256>,
}

impl Message for SnapshotManifestResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_SNAPSHOT_MANIFEST_RESPONSE }
}

impl Encodable for SnapshotManifestResponse {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4)
            .append(&self.request_id)
            .append(&self.checkpoint)
            .append(&self.state_root)
            .append_list(&self.chunk_hashes);
    }
}

impl Decodable for SnapshotManifestResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(SnapshotManifestResponse {
            request_id: rlp.val_at(0)?,
            checkpoint: rlp.val_at(1)?,
            state_root: rlp.val_at(2)?,
            chunk_hashes: rlp.list_at(3)?,
        })
    }
}
