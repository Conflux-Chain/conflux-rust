// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        Context, GetBlocks, GetCompactBlocksResponse, Handleable, Key,
        KeyContainer, Message, MsgId, RequestId,
    },
    request_manager::Request,
    synchronization_protocol_handler::{
        MAX_BLOCKS_TO_SEND, MAX_HEADERS_TO_SEND,
    },
    Error, ProtocolConfiguration,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    any::Any,
    ops::{Deref, DerefMut},
    time::Duration,
};

#[derive(Debug, PartialEq, Default)]
pub struct GetCompactBlocks {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

impl Request for GetCompactBlocks {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id.set_request_id(request_id);
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
    }

    fn on_removed(&self, inflight_keys: &mut KeyContainer) {
        let msg_type = MsgId::GET_BLOCKS.into();
        for hash in self.hashes.iter() {
            inflight_keys.remove(msg_type, Key::Hash(*hash));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &mut KeyContainer) {
        let msg_type = MsgId::GET_BLOCKS.into();
        self.hashes
            .retain(|h| inflight_keys.add(msg_type, Key::Hash(*h)));
    }

    fn is_empty(&self) -> bool { self.hashes.is_empty() }

    fn resend(&self) -> Option<Box<Request>> {
        Some(Box::new(GetBlocks {
            request_id: 0.into(),
            with_public: true,
            hashes: self.hashes.iter().cloned().collect(),
        }))
    }
}

impl Handleable for GetCompactBlocks {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let mut compact_blocks = Vec::with_capacity(self.hashes.len());
        let mut blocks = Vec::new();

        for hash in self.hashes.iter() {
            if let Some(compact_block) =
                ctx.manager.graph.data_man.compact_block_by_hash(hash)
            {
                if (compact_blocks.len() as u64) < MAX_HEADERS_TO_SEND {
                    compact_blocks.push(compact_block);
                }
            } else if let Some(block) = ctx.manager.graph.block_by_hash(hash) {
                debug!("Have complete block but no compact block, return complete block instead");
                if (blocks.len() as u64) < MAX_BLOCKS_TO_SEND {
                    blocks.push(block.as_ref().clone());
                }
            } else {
                warn!(
                    "Peer {} requested non-existent compact block {}",
                    ctx.peer, hash
                );
            }
        }

        let response = GetCompactBlocksResponse {
            request_id: self.request_id.clone(),
            compact_blocks,
            blocks,
        };

        ctx.send_response(&response)
    }
}

impl Message for GetCompactBlocks {
    fn msg_id(&self) -> MsgId { MsgId::GET_CMPCT_BLOCKS }

    fn msg_name(&self) -> &'static str { "GetCompactBlocks" }
}

impl Deref for GetCompactBlocks {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetCompactBlocks {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetCompactBlocks {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.hashes);
    }
}

impl Decodable for GetCompactBlocks {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetCompactBlocks {
            request_id: rlp.val_at(0)?,
            hashes: rlp.list_at(1)?,
        })
    }
}
