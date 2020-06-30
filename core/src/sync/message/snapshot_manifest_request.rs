// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockExecutionResult,
    message::{
        GetMaybeRequestId, Message, MessageProtocolVersionBound, MsgId,
        RequestId, SetRequestId,
    },
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        consensus_internal::REWARD_EPOCH_COUNT,
    },
    sync::{
        message::{
            msgid, Context, DynamicCapability, Handleable, KeyContainer,
            SnapshotManifestResponse,
        },
        request_manager::{AsAny, Request},
        state::storage::{RangedManifest, SnapshotSyncCandidate},
        Error, ProtocolConfiguration, SYNC_PROTO_V1, SYNC_PROTO_V2,
    },
};
use cfx_types::H256;
use network::service::ProtocolVersion;
use primitives::{EpochNumber, StateRoot};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct SnapshotManifestRequest {
    pub request_id: u64,
    pub snapshot_to_sync: SnapshotSyncCandidate,
    pub start_chunk: Option<Vec<u8>>,
    pub trusted_blame_block: Option<H256>,
}

build_msg_with_request_id_impl! {
    SnapshotManifestRequest, msgid::GET_SNAPSHOT_MANIFEST,
    "SnapshotManifestRequest", SYNC_PROTO_V1, SYNC_PROTO_V2
}

impl Handleable for SnapshotManifestRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        // TODO Handle the case where we cannot serve the snapshot
        let snapshot_merkle_root;
        let manifest = match RangedManifest::load(
            &self.snapshot_to_sync,
            self.start_chunk.clone(),
            &ctx.manager.graph.data_man.storage_manager,
            ctx.manager.protocol_config.chunk_size_byte,
        ) {
            Ok(Some((m, merkle_root))) => {
                snapshot_merkle_root = merkle_root;
                m
            }
            _ => {
                // Return an empty response to indicate that we cannot serve the
                // state
                ctx.send_response(&SnapshotManifestResponse {
                    request_id: self.request_id,
                    ..Default::default()
                })?;
                return Ok(());
            }
        };

        let (state_root_vec, receipt_blame_vec, bloom_blame_vec) =
            self.get_blame_states(ctx).unwrap_or_default();
        let block_receipts = self.get_block_receipts(ctx).unwrap_or_default();

        debug!("handle SnapshotManifestRequest {:?}", self,);
        ctx.send_response(&SnapshotManifestResponse {
            request_id: self.request_id,
            manifest,
            state_root_vec,
            receipt_blame_vec,
            bloom_blame_vec,
            block_receipts,
            snapshot_merkle_root,
        })
    }
}

impl SnapshotManifestRequest {
    pub fn new(
        snapshot_sync_candidate: SnapshotSyncCandidate,
        trusted_blame_block: H256,
    ) -> Self
    {
        SnapshotManifestRequest {
            request_id: 0,
            snapshot_to_sync: snapshot_sync_candidate,
            start_chunk: None,
            trusted_blame_block: Some(trusted_blame_block),
        }
    }

    pub fn is_initial_request(&self) -> bool {
        self.trusted_blame_block.is_some()
    }

    fn get_block_receipts(
        &self, ctx: &Context,
    ) -> Option<Vec<BlockExecutionResult>> {
        let mut epoch_receipts = Vec::new();
        let mut epoch_hash =
            self.snapshot_to_sync.get_snapshot_epoch_id().clone();
        for _ in 0..REWARD_EPOCH_COUNT {
            if let Some(block) =
                ctx.manager.graph.data_man.block_header_by_hash(&epoch_hash)
            {
                match ctx.manager.graph.consensus.get_block_hashes_by_epoch(
                    EpochNumber::Number(block.height()),
                ) {
                    Ok(ordered_executable_epoch_blocks) => {
                        for hash in &ordered_executable_epoch_blocks {
                            match ctx
                                .manager
                                .graph
                                .data_man
                                .block_execution_result_by_hash_with_epoch(
                                    hash,
                                    &epoch_hash,
                                    false, /* update_pivot_assumption */
                                    false, /* update_cache */
                                ) {
                                Some(block_execution_result) => {
                                    epoch_receipts.push(block_execution_result);
                                }
                                None => {
                                    debug!("Cannot get execution result for hash={:?} epoch_hash={:?}",
                                        hash, epoch_hash
                                    );
                                    return None;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        debug!(
                            "Cannot get block hashes for epoch {}",
                            block.height()
                        );
                        return None;
                    }
                }
                // We have reached original genesis
                if block.height() == 0 {
                    break;
                }
                epoch_hash = block.parent_hash().clone();
            } else {
                warn!(
                    "failed to find block={} in db, peer={}",
                    epoch_hash, ctx.node_id
                );
                return None;
            }
        }
        Some(epoch_receipts)
    }

    /// return an empty vec if some information not exist in db, caller may find
    /// another peer to send the request; otherwise return a state_blame_vec
    /// of the requested block
    fn get_blame_states(
        &self, ctx: &Context,
    ) -> Option<(Vec<StateRoot>, Vec<H256>, Vec<H256>)> {
        let trusted_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(&self.trusted_blame_block?)?;
        let snapshot_epoch_block =
            ctx.manager.graph.data_man.block_header_by_hash(
                self.snapshot_to_sync.get_snapshot_epoch_id(),
            )?;
        if trusted_block.height() < snapshot_epoch_block.height() {
            warn!(
                "receive invalid snapshot manifest request from peer={}",
                ctx.node_id
            );
            return None;
        }
        let mut block_hash = trusted_block.hash();
        let mut trusted_block_height = trusted_block.height();
        let mut blame_count = trusted_block.blame();
        let mut deferred_block_hash = block_hash;
        for _ in 0..DEFERRED_STATE_EPOCH_COUNT {
            deferred_block_hash = *ctx
                .manager
                .graph
                .data_man
                .block_header_by_hash(&deferred_block_hash)
                .expect("All headers exist")
                .parent_hash();
        }

        let min_vec_len = if snapshot_epoch_block.height() == 0 {
            trusted_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - snapshot_epoch_block.height()
                + 1
        } else {
            trusted_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - snapshot_epoch_block.height()
                + REWARD_EPOCH_COUNT
        };
        let mut state_root_vec = Vec::with_capacity(min_vec_len as usize);
        let mut receipt_blame_vec = Vec::with_capacity(min_vec_len as usize);
        let mut bloom_blame_vec = Vec::with_capacity(min_vec_len as usize);

        // loop until we have enough length of `state_root_vec`
        loop {
            if let Some(block) =
                ctx.manager.graph.data_man.block_header_by_hash(&block_hash)
            {
                // We've jumped to another trusted block.
                if block.height() + blame_count as u64 + 1
                    == trusted_block_height
                {
                    trusted_block_height = block.height();
                    blame_count = block.blame()
                }
                if let Some(commitment) = ctx
                    .manager
                    .graph
                    .data_man
                    .get_epoch_execution_commitment_with_db(
                        &deferred_block_hash,
                    )
                {
                    state_root_vec.push(
                        commitment.state_root_with_aux_info.state_root.clone(),
                    );
                    receipt_blame_vec.push(commitment.receipts_root);
                    bloom_blame_vec.push(commitment.logs_bloom_hash);
                } else {
                    warn!(
                        "failed to find block={} in db, peer={}",
                        block_hash, ctx.node_id
                    );
                    return None;
                }
                // We've collected enough states.
                if block.height() + blame_count as u64 == trusted_block_height
                    && state_root_vec.len() >= min_vec_len as usize
                {
                    break;
                }
                block_hash = *block.parent_hash();
                deferred_block_hash = *ctx
                    .manager
                    .graph
                    .data_man
                    .block_header_by_hash(&deferred_block_hash)
                    .expect("All headers received")
                    .parent_hash();
            } else {
                warn!(
                    "failed to find block={} in db, peer={}",
                    block_hash, ctx.node_id
                );
                return None;
            }
        }

        Some((state_root_vec, receipt_blame_vec, bloom_blame_vec))
    }
}

impl AsAny for SnapshotManifestRequest {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Request for SnapshotManifestRequest {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.snapshot_manifest_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<dyn Request>> { None }

    fn required_capability(&self) -> Option<DynamicCapability> { None }
}
