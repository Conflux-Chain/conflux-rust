// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, RequestId},
    sync::{
        message::{
            Context, GetBlocksResponse, GetBlocksWithPublicResponse,
            Handleable, Key, KeyContainer,
        },
        request_manager::Request,
        synchronization_protocol_handler::MAX_PACKET_SIZE,
        Error, ErrorKind, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use primitives::Block;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    any::Any,
    ops::{Deref, DerefMut},
    time::Duration,
};

#[derive(Debug, PartialEq, Default, Clone)]
pub struct GetBlocks {
    pub request_id: RequestId,
    pub with_public: bool,
    pub hashes: Vec<H256>,
}

impl Request for GetBlocks {
    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
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

impl GetBlocks {
    fn get_blocks(&self, ctx: &Context, with_public: bool) -> Vec<Block> {
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
            request_id: self.request_id.clone(),
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
            request_id: self.request_id.clone(),
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
        if self.hashes.is_empty() {
            return Ok(());
        }

        let blocks = self.get_blocks(ctx, self.with_public);
        if self.with_public {
            self.send_response_with_public(ctx, blocks)
        } else {
            self.send_response(ctx, blocks)
        }
    }
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
        let with_public_n = if self.with_public { 1 as u8 } else { 0 as u8 };
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
