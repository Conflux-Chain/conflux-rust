// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, RequestId},
    sync::{
        message::{
            msgid, Context, GetBlocksResponse, GetBlocksWithPublicResponse,
            Handleable, Key, KeyContainer,
        },
        request_manager::{AsAny, Request},
        Error, ErrorKind, ProtocolConfiguration,
    },
    NodeType,
};
use cfx_parameters::sync::MAX_PACKET_SIZE;
use cfx_types::H256;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::Block;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{any::Any, time::Duration};

#[derive(Debug, PartialEq, Default, Clone, DeriveMallocSizeOf)]
pub struct GetBlocks {
    pub request_id: RequestId,
    pub with_public: bool,
    pub hashes: Vec<H256>,
    // This field specifies what node type of peers this
    // request needs to be sent to.
    pub preferred_node_type: Option<NodeType>,
}

impl Encodable for GetBlocks {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.request_id)
            .append(&self.with_public)
            .append_list(&self.hashes);
    }
}

impl Decodable for GetBlocks {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(GetBlocks {
            request_id: rlp.val_at(0)?,
            with_public: rlp.val_at(1)?,
            hashes: rlp.list_at(2)?,
            preferred_node_type: None,
        })
    }
}

impl AsAny for GetBlocks {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Request for GetBlocks {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
    }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut inflight_blocks = inflight_keys.write(self.msg_id());
        let mut net_inflight_blocks =
            inflight_keys.write(msgid::NET_INFLIGHT_BLOCKS);
        for hash in self.hashes.iter() {
            inflight_blocks.remove(&Key::Hash(*hash));
            net_inflight_blocks.remove(&Key::Hash(*hash));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(self.msg_id());
        self.hashes.retain(|h| inflight_keys.insert(Key::Hash(*h)));
    }

    fn is_empty(&self) -> bool { self.hashes.is_empty() }

    fn resend(&self) -> Option<Box<dyn Request>> {
        Some(Box::new(self.clone()))
    }

    fn preferred_node_type(&self) -> Option<NodeType> {
        self.preferred_node_type.clone()
    }
}

impl GetBlocks {
    fn get_blocks(&self, ctx: &Context, with_public: bool) -> Vec<Block> {
        debug!("Received GetBlocks: {:?}", self);
        let mut blocks = Vec::new();
        let mut packet_size_left = MAX_PACKET_SIZE;

        for hash in self.hashes.iter() {
            if let Some(block) = ctx.manager.graph.block_by_hash(hash) {
                let block_size = if with_public {
                    block.approximated_rlp_size_with_public()
                } else {
                    block.approximated_rlp_size()
                };

                if packet_size_left >= block_size {
                    packet_size_left -= block_size;
                    blocks.push(block.as_ref().clone());
                } else {
                    break;
                }
            }
        }

        blocks
    }

    fn send_response_with_public(
        &self, ctx: &Context, blocks: Vec<Block>,
    ) -> Result<(), Error> {
        let mut response = GetBlocksWithPublicResponse {
            request_id: self.request_id,
            blocks,
        };

        while let Err(e) = ctx.send_response(&response) {
            if GetBlocks::is_oversize_packet_err(&e) {
                let block_count = response.blocks.len() / 2;
                response.blocks.truncate(block_count);
            } else {
                return Err(e.into());
            }
        }

        Ok(())
    }

    fn is_oversize_packet_err(e: &Error) -> bool {
        match e.kind() {
            ErrorKind::Network(kind) => match kind {
                network::ErrorKind::OversizedPacket => true,
                _ => false,
            },
            _ => false,
        }
    }

    fn send_response(
        &self, ctx: &Context, blocks: Vec<Block>,
    ) -> Result<(), Error> {
        let mut response = GetBlocksResponse {
            request_id: self.request_id,
            blocks,
        };

        while let Err(e) = ctx.send_response(&response) {
            if GetBlocks::is_oversize_packet_err(&e) {
                let block_count = response.blocks.len() / 2;
                response.blocks.truncate(block_count);
            } else {
                return Err(e.into());
            }
        }

        Ok(())
    }
}

impl Handleable for GetBlocks {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let blocks = self.get_blocks(ctx, self.with_public);
        if self.with_public {
            self.send_response_with_public(ctx, blocks)
        } else {
            self.send_response(ctx, blocks)
        }
    }
}
