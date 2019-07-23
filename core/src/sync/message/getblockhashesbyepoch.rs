// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        GetBlockHashesResponse, Message, MsgId, Request, RequestContext,
        RequestId,
    },
    synchronization_protocol_handler::MAX_EPOCHS_TO_SEND,
    Error,
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq)]
pub struct GetBlockHashesByEpoch {
    pub request_id: RequestId,
    pub epochs: Vec<u64>,
}

impl Request for GetBlockHashesByEpoch {
    fn handle(&self, context: &RequestContext) -> Result<(), Error> {
        if self.epochs.is_empty() {
            return Ok(());
        }

        let hashes = self
            .epochs
            .iter()
            .take(MAX_EPOCHS_TO_SEND as usize)
            .map(|&e| context.graph.get_block_hashes_by_epoch(e))
            .filter_map(Result::ok)
            .fold(vec![], |mut res, sub| {
                res.extend(sub);
                res
            });

        let response = GetBlockHashesResponse {
            request_id: self.request_id.clone(),
            hashes,
        };

        context.send_response(&response)
    }
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
            .append_list(&self.epochs);
    }
}

impl Decodable for GetBlockHashesByEpoch {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlockHashesByEpoch {
            request_id: rlp.val_at(0)?,
            epochs: rlp.list_at(1)?,
        })
    }
}
