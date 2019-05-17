// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{Message, MsgId, RequestId};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq)]
pub struct GetBlockHashesByEpoch {
    pub request_id: RequestId,
    pub epoch_number: u64,
}

impl Message for GetBlockHashesByEpoch {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HASHES_BY_EPOCH }
}

impl Deref for GetBlockHashesByEpoch {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockHashesByEpoch {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlockHashesByEpoch {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append(&self.epoch_number);
    }
}

impl Decodable for GetBlockHashesByEpoch {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlockHashesByEpoch {
            request_id: rlp.val_at(0)?,
            epoch_number: rlp.val_at(1)?,
        })
    }
}
