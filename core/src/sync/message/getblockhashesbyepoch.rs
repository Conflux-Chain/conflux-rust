// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        Context, GetBlockHashesResponse, Handleable, Key, KeyContainer,
        Message, MsgId, RequestId,
    },
    request_manager::Request,
    synchronization_protocol_handler::MAX_EPOCHS_TO_SEND,
    Error, ProtocolConfiguration,
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    any::Any,
    ops::{Deref, DerefMut},
    time::Duration,
};

#[derive(Debug, PartialEq, Clone)]
pub struct GetBlockHashesByEpoch {
    pub request_id: RequestId,
    pub epochs: Vec<u64>,
}

impl Request for GetBlockHashesByEpoch {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id.set_request_id(request_id);
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.headers_request_timeout
    }

    fn on_removed(&self, inflight_keys: &mut KeyContainer) {
        let msg_type = self.msg_id().into();
        for epoch in self.epochs.iter() {
            inflight_keys.remove(msg_type, Key::Num(*epoch));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &mut KeyContainer) {
        let msg_type = self.msg_id().into();
        self.epochs
            .retain(|epoch| inflight_keys.add(msg_type, Key::Num(*epoch)));
    }

    fn is_empty(&self) -> bool { self.epochs.is_empty() }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }
}

impl Handleable for GetBlockHashesByEpoch {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        if self.epochs.is_empty() {
            return Ok(());
        }

        let hashes = self
            .epochs
            .iter()
            .take(MAX_EPOCHS_TO_SEND as usize)
            .map(|&e| ctx.manager.graph.get_block_hashes_by_epoch(e))
            .filter_map(Result::ok)
            .fold(vec![], |mut res, sub| {
                res.extend(sub);
                res
            });

        let response = GetBlockHashesResponse {
            request_id: self.request_id.clone(),
            hashes,
        };

        ctx.send_response(&response)
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
