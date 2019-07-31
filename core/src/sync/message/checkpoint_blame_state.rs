// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{HasRequestId, Message, MsgId, RequestId},
    sync::{
        message::{msgid, Context, Handleable, KeyContainer},
        request_manager::Request,
        Error, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
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

build_msg_impl! { CheckpointBlameStateRequest, msgid::GET_CHECKPOINT_BLAME_STATE_REQUEST, "CheckpointBlameStateRequest" }
build_has_request_id_impl! { CheckpointBlameStateRequest }

impl Request for CheckpointBlameStateRequest {
    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.headers_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &mut KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &mut KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }
}

impl Handleable for CheckpointBlameStateRequest {
    /// return an empty vec if some information not exist in db, caller may find
    /// another peer to send the request; otherwise return a state_blame_vec
    /// of the requested block
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let trusted_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(&self.trusted_blame_block);
        if trusted_block.is_none() {
            warn!(
                "failed to find trusted_blame_block={} in db from peer={}",
                self.trusted_blame_block, ctx.peer,
            );
            let response = CheckpointBlameStateResponse {
                request_id: self.request_id,
                state_blame_vec: Vec::new(),
            };
            return ctx.send_response(&response);
        }
        let trusted_block = trusted_block.unwrap();

        let mut state_blame_vec = Vec::new();
        let mut block_hash = trusted_block.hash();
        let mut request_invalid = false;
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
                    request_invalid = true;
                    break;
                }
            } else {
                warn!("failed to find ConsensusGraphExecutionInfo for block={} in db, peer={}", block_hash, ctx.peer);
                request_invalid = true;
                break;
            }
        }

        let response = CheckpointBlameStateResponse {
            request_id: self.request_id,
            state_blame_vec: if request_invalid {
                Vec::new()
            } else {
                state_blame_vec
            },
        };

        ctx.send_response(&response)
    }
}

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct CheckpointBlameStateResponse {
    pub request_id: u64,
    pub state_blame_vec: Vec<H256>,
}

build_msg_impl! { CheckpointBlameStateResponse, msgid::GET_CHECKPOINT_BLAME_STATE_RESPONSE, "CheckpointBlameStateResponse" }

impl Handleable for CheckpointBlameStateResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        ctx.match_request(self.request_id)?;

        ctx.manager
            .state_sync
            .handle_checkpoint_blame_state_response(ctx, &self.state_blame_vec);
        Ok(())
    }
}
