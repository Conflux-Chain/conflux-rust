// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, RequestId},
    parameters::sync::{MAX_BLOCKS_TO_SEND, MAX_HEADERS_TO_SEND},
    sync::{
        message::{
            msgid, Context, GetBlocks, GetCompactBlocksResponse, Handleable,
            Key, KeyContainer,
        },
        request_manager::Request,
        Error, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, PartialEq, Default, RlpDecodable, RlpEncodable)]
pub struct GetCompactBlocks {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

impl Request for GetCompactBlocks {
    fn as_message(&self) -> &dyn Message { self }

    fn as_any(&self) -> &dyn Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
    }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(msgid::GET_BLOCKS);
        for hash in self.hashes.iter() {
            inflight_keys.remove(&Key::Hash(*hash));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(msgid::GET_BLOCKS);
        self.hashes.retain(|h| inflight_keys.insert(Key::Hash(*h)));
    }

    fn is_empty(&self) -> bool { self.hashes.is_empty() }

    fn resend(&self) -> Option<Box<dyn Request>> {
        Some(Box::new(GetBlocks {
            request_id: 0,
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
            request_id: self.request_id,
            compact_blocks,
            blocks,
        };

        ctx.send_response(&response)
    }
}
