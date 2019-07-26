// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        Context, GetBlockHeadersResponse, Handleable, Key, KeyContainer,
        Message, MsgId, RequestId,
    },
    request_manager::Request,
    synchronization_protocol_handler::MAX_HEADERS_TO_SEND,
    Error, ProtocolConfiguration,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    any::Any,
    cmp::min,
    ops::{Deref, DerefMut},
    time::Duration,
};

#[derive(Debug, PartialEq, Clone)]
pub struct GetBlockHeaderChain {
    pub request_id: RequestId,
    pub hash: H256,
    pub max_blocks: u64,
}

impl Request for GetBlockHeaderChain {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id.set_request_id(request_id);
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.headers_request_timeout
    }

    fn on_removed(&self, inflight_keys: &mut KeyContainer) {
        inflight_keys.remove(
            MsgId::GET_BLOCK_HEADERS.into(),
            Key::Hash(self.hash.clone()),
        );
    }

    fn with_inflight(&mut self, inflight_keys: &mut KeyContainer) {
        if !inflight_keys.add(
            MsgId::GET_BLOCK_HEADERS.into(),
            Key::Hash(self.hash.clone()),
        ) {
            self.hash = H256::zero();
        }
    }

    fn is_empty(&self) -> bool { self.hash.is_zero() }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }
}

impl Handleable for GetBlockHeaderChain {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let mut hash = self.hash;
        let mut block_headers_resp = GetBlockHeadersResponse::default();
        block_headers_resp.set_request_id(self.request_id());

        for _ in 0..min(MAX_HEADERS_TO_SEND, self.max_blocks) {
            let header = ctx.manager.graph.block_header_by_hash(&hash);
            if header.is_none() {
                break;
            }
            let header = header.unwrap();
            block_headers_resp.headers.push(header.clone());
            if hash == ctx.manager.graph.genesis_hash() {
                break;
            }
            hash = header.parent_hash().clone();
        }

        debug!(
            "Returned {:?} block headers to peer {:?}",
            block_headers_resp.headers.len(),
            ctx.peer
        );

        ctx.send_response(&block_headers_resp)
    }
}

impl Message for GetBlockHeaderChain {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HEADER_CHAIN }
}

impl Deref for GetBlockHeaderChain {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockHeaderChain {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlockHeaderChain {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append(&self.hash)
            .append(&self.max_blocks);
    }
}

impl Decodable for GetBlockHeaderChain {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlockHeaderChain {
            request_id: rlp.val_at(0)?,
            hash: rlp.val_at(1)?,
            max_blocks: rlp.val_at(2)?,
        })
    }
}
