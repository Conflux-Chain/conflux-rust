// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{Message, MsgId, RequestId};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq)]
pub struct GetBlockHeaders {
    pub request_id: RequestId,
    pub hash: H256,
    pub max_blocks: u64,
}

impl Message for GetBlockHeaders {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HEADERS }
}

impl Deref for GetBlockHeaders {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockHeaders {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlockHeaders {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append(&self.hash)
            .append(&self.max_blocks);
    }
}

impl Decodable for GetBlockHeaders {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlockHeaders {
            request_id: rlp.val_at(0)?,
            hash: rlp.val_at(1)?,
            max_blocks: rlp.val_at(2)?,
        })
    }
}
