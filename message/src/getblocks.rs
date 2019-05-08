// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{Message, MsgId, RequestId};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Default)]
pub struct GetBlocks {
    pub request_id: RequestId,
    pub with_public: bool,
    pub hashes: Vec<H256>,
}

impl Message for GetBlocks {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCKS }
}

impl Deref for GetBlocks {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlocks {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlocks {
    fn rlp_append(&self, stream: &mut RlpStream) {
        let with_public_n = if self.with_public {
            1 as u8
        } else {
            0 as u8
        };
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append(&with_public_n)
            .append_list(&self.hashes);
    }
}

impl Decodable for GetBlocks {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlocks {
            request_id: rlp.val_at(0)?,
            with_public: rlp.val_at::<u8>(1)? == 1,
            hashes: rlp.list_at(2)?,
        })
    }
}
