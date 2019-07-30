// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{HasRequestId, Message, RequestId},
    sync::{
        message::{
            Context, GetBlockHeadersResponse, Handleable, Key, KeyContainer,
        },
        request_manager::Request,
        synchronization_protocol_handler::MAX_HEADERS_TO_SEND,
        Error, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    any::Any,
    ops::{Deref, DerefMut},
    time::Duration,
};

#[derive(Debug, PartialEq, Clone)]
pub struct GetBlockHeaders {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

impl Request for GetBlockHeaders {
    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.headers_request_timeout
    }

    fn on_removed(&self, inflight_keys: &mut KeyContainer) {
        let msg_type = self.msg_id().into();
        for hash in self.hashes.iter() {
            inflight_keys.remove(msg_type, Key::Hash(*hash));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &mut KeyContainer) {
        let msg_type = self.msg_id().into();
        self.hashes
            .retain(|h| inflight_keys.add(msg_type, Key::Hash(*h)));
    }

    fn is_empty(&self) -> bool { self.hashes.is_empty() }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }
}

impl Handleable for GetBlockHeaders {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        if self.hashes.is_empty() {
            return Ok(());
        }

        let headers = self
            .hashes
            .iter()
            .take(MAX_HEADERS_TO_SEND as usize)
            .filter_map(|hash| ctx.manager.graph.block_header_by_hash(&hash))
            .collect();

        let mut block_headers_resp = GetBlockHeadersResponse::default();
        block_headers_resp.set_request_id(self.request_id);
        block_headers_resp.headers = headers;

        debug!(
            "Returned {:?} block headers to peer {:?}",
            block_headers_resp.headers.len(),
            ctx.peer,
        );

        ctx.send_response(&block_headers_resp)
    }
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
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.hashes);
    }
}

impl Decodable for GetBlockHeaders {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlockHeaders {
            request_id: rlp.val_at(0)?,
            hashes: rlp.list_at(1)?,
        })
    }
}
