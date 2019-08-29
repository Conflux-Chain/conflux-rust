// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{HasRequestId, Message, MsgId, RequestId},
    storage::{ChunkKey, RangedManifest},
    sync::{
        message::{
            msgid, Context, DynamicCapability, Handleable, KeyContainer,
        },
        request_manager::Request,
        state::snapshot_manifest_response::SnapshotManifestResponse,
        Error, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct SnapshotManifestRequest {
    pub request_id: u64,
    pub checkpoint: H256,
    pub start_chunk: Option<ChunkKey>,
    pub trusted_blame_block: Option<H256>,
}

build_msg_impl! { SnapshotManifestRequest, msgid::GET_SNAPSHOT_MANIFEST, "SnapshotManifestRequest" }
build_has_request_id_impl! { SnapshotManifestRequest }

impl Handleable for SnapshotManifestRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let manifest =
            match RangedManifest::load(&self.checkpoint, &self.start_chunk) {
                Ok(Some(m)) => m,
                _ => RangedManifest::default(),
            };

        ctx.send_response(&SnapshotManifestResponse {
            request_id: self.request_id,
            checkpoint: self.checkpoint.clone(),
            manifest,
            state_blame_vec: self.get_blame_states(ctx).unwrap_or_default(),
        })
    }
}

impl SnapshotManifestRequest {
    pub fn new(checkpoint: H256, trusted_blame_block: H256) -> Self {
        SnapshotManifestRequest {
            request_id: 0,
            checkpoint,
            start_chunk: None,
            trusted_blame_block: Some(trusted_blame_block),
        }
    }

    pub fn new_with_start_chunk(
        checkpoint: H256, start_chunk: ChunkKey,
    ) -> Self {
        SnapshotManifestRequest {
            request_id: 0,
            checkpoint,
            start_chunk: Some(start_chunk),
            trusted_blame_block: None,
        }
    }

    /// return an empty vec if some information not exist in db, caller may find
    /// another peer to send the request; otherwise return a state_blame_vec
    /// of the requested block
    fn get_blame_states(self, ctx: &Context) -> Option<Vec<H256>> {
        let trusted_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(&self.trusted_blame_block?)?;

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

        if request_invalid {
            None
        } else {
            Some(state_blame_vec)
        }
    }
}

impl Request for SnapshotManifestRequest {
    fn as_message(&self) -> &dyn Message { self }

    fn as_any(&self) -> &dyn Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.headers_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<dyn Request>> {
        Some(Box::new(self.clone()))
    }

    fn required_capability(&self) -> Option<DynamicCapability> {
        Some(DynamicCapability::ServeCheckpoint(Some(
            self.checkpoint.clone(),
        )))
    }
}
