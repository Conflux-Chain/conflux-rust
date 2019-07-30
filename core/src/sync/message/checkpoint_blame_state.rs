// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable, KeyContainer, Message, MsgId},
    request_manager::Request,
    Error, ErrorKind, ProtocolConfiguration,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{any::Any, time::Duration};

#[derive(Debug, Clone)]
pub struct CheckpointBlameStateRequest {
    pub request_id: u64,
    pub trusted_blame_block: H256,
}

impl CheckpointBlameStateRequest {
    pub fn new(trusted_blame_block: H256) -> Self {
        Self {
            request_id: 0,
            trusted_blame_block,
        }
    }
}

impl Request for CheckpointBlameStateRequest {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id = request_id;
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.blocks_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &mut KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &mut KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }
}

impl Handleable for CheckpointBlameStateRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let trusted_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(&self.trusted_blame_block);
        if trusted_block.is_none() {
            warn!(
                "invalid trusted_blame_block={} in CheckpointBlameStateRequest from peer={}",
                self.trusted_blame_block,
                ctx.peer,
            );
            return Err(ErrorKind::Invalid.into());
        }
        let trusted_block = trusted_block.unwrap();

        let mut state_blame_vec = Vec::new();
        let mut block_hash = trusted_block.hash();
        loop {
            if let Some(exec_info) = ctx
                .manager
                .graph
                .data_man
                .consensus_graph_execution_info_from_db(&block_hash)
            {
                state_blame_vec.push(exec_info.original_deferred_state_root);
                if state_blame_vec.len() == trusted_block.blame() as usize + 1 {
                    break;
                }
                if let Some(block) =
                    ctx.manager.graph.data_man.block_header_by_hash(&block_hash)
                {
                    block_hash = block.parent_hash().clone();
                } else {
                    warn!(
                        "failed to find block={} in db, peer={}",
                        block_hash, ctx.peer
                    );
                    return Err(ErrorKind::Invalid.into());
                }
            } else {
                warn!("failed to find ConsensusGraphExecutionInfo for block={} in db, peer={}", block_hash, ctx.peer);
                return Err(ErrorKind::Invalid.into());
            }
        }

        let response = CheckpointBlameStateResponse {
            request_id: self.request_id,
            state_blame_vec,
        };

        ctx.send_response(&response)
    }
}

impl Message for CheckpointBlameStateRequest {
    fn msg_id(&self) -> MsgId { MsgId::GET_CHECKPOINT_BLAME_STATE_REQUEST }

    fn msg_name(&self) -> &'static str { "GetCheckpointBlameStateRequest" }
}

impl Encodable for CheckpointBlameStateRequest {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append(&self.trusted_blame_block);
    }
}

impl Decodable for CheckpointBlameStateRequest {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(CheckpointBlameStateRequest {
            request_id: rlp.val_at(0)?,
            trusted_blame_block: rlp.val_at(1)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CheckpointBlameStateResponse {
    pub request_id: u64,
    pub state_blame_vec: Vec<H256>,
}

impl Handleable for CheckpointBlameStateResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        ctx.match_request(self.request_id)?;

        ctx.manager
            .state_sync
            .handle_checkpoint_blame_state_response(ctx, &self.state_blame_vec);
        Ok(())
    }
}

impl Message for CheckpointBlameStateResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_HEADERS_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetCheckpointBlameStateResponse" }
}

impl Encodable for CheckpointBlameStateResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.state_blame_vec);
    }
}

impl Decodable for CheckpointBlameStateResponse {
    fn decode(rlp: &Rlp) -> Result<CheckpointBlameStateResponse, DecoderError> {
        Ok(CheckpointBlameStateResponse {
            request_id: rlp.val_at(0)?,
            state_blame_vec: rlp.list_at(1)?,
        })
    }
}
