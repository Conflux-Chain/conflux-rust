// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockExecutionResult,
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        consensus_internal::REWARD_EPOCH_COUNT,
    },
    sync::{
        message::{Context, DynamicCapability, Handleable, KeyContainer},
        request_manager::Request,
        state::{
            snapshot_manifest_response::SnapshotManifestResponse,
            storage::RangedManifest,
        },
        Error, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use primitives::StateRoot;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::time::Duration;

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct SnapshotManifestRequest {
    pub request_id: u64,
    pub snapshot_epoch_id: H256,
    pub start_chunk: Option<Vec<u8>>,
    pub trusted_blame_block: Option<H256>,
}

impl Handleable for SnapshotManifestRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        // TODO Handle the case where we cannot serve the snapshot
        let manifest = match RangedManifest::load(
            &self.snapshot_epoch_id,
            self.start_chunk.clone(),
            &ctx.manager.graph.data_man.storage_manager,
        ) {
            Ok(Some(m)) => m,
            _ => RangedManifest::default(),
        };

        let (state_root_vec, receipt_blame_vec, bloom_blame_vec) =
            self.get_blame_states(ctx).unwrap_or_default();
        let block_receipts = self.get_block_receipts(ctx).unwrap_or_default();
        let trusted_snapshot_blame_block = ctx
            .manager
            .graph
            .consensus
            .get_trusted_blame_block_for_snapshot(&self.snapshot_epoch_id)
            .unwrap();
        // TODO Ensure the state_root is pointed to snapshot_epoch_id
        let block_with_trusted_state_root = ctx
            .manager
            .graph
            .data_man
            .get_parent_epochs_for(
                trusted_snapshot_blame_block,
                DEFERRED_STATE_EPOCH_COUNT,
            )
            .0;
        let snapshot_state_root = ctx
            .manager
            .graph
            .data_man
            .get_epoch_execution_commitment_with_db(
                &block_with_trusted_state_root,
            )
            .unwrap()
            .state_root_with_aux_info
            .state_root;
        assert_eq!(
            snapshot_state_root.compute_state_root_hash(),
            *ctx.manager
                .graph
                .data_man
                .block_header_by_hash(&trusted_snapshot_blame_block)
                .unwrap()
                .deferred_state_root()
        );
        debug!("handle SnapshotManifestRequest: return snapshot_state_root={:?} in block {:?}", snapshot_state_root, trusted_snapshot_blame_block);
        ctx.send_response(&SnapshotManifestResponse {
            request_id: self.request_id,
            checkpoint: self.snapshot_epoch_id.clone(),
            manifest,
            state_root_vec,
            receipt_blame_vec,
            bloom_blame_vec,
            block_receipts,
            snapshot_state_root,
        })
    }
}

impl SnapshotManifestRequest {
    pub fn new(checkpoint: H256, trusted_blame_block: H256) -> Self {
        SnapshotManifestRequest {
            request_id: 0,
            snapshot_epoch_id: checkpoint,
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
        let mut epoch_hash = self.snapshot_epoch_id;
        for _ in 0..REWARD_EPOCH_COUNT {
            if let Some(block) =
                ctx.manager.graph.data_man.block_header_by_hash(&epoch_hash)
            {
                match ctx
                    .manager
                    .graph
                    .consensus
                    .inner
                    .read()
                    .block_hashes_by_epoch(block.height())
                {
                    Ok(ordered_executable_epoch_blocks) => {
                        for hash in &ordered_executable_epoch_blocks {
                            match ctx
                                .manager
                                .graph
                                .data_man
                                .block_execution_result_by_hash_with_epoch(
                                    hash,
                                    &epoch_hash,
                                    false, /* update_cache */
                                ) {
                                Some(block_execution_result) => {
                                    epoch_receipts.push(block_execution_result);
                                }
                                None => {
                                    return None;
                                }
                            }
                        }
                    }
                    Err(_) => {
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
                    epoch_hash, ctx.peer
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
        let checkpoint_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(&self.snapshot_epoch_id)?;
        if trusted_block.height() < checkpoint_block.height() {
            warn!(
                "receive invalid snapshot manifest request from peer={}",
                ctx.peer
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

        let min_vec_len = if checkpoint_block.height() == 0 {
            trusted_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - checkpoint_block.height()
                + 1
        } else {
            trusted_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - checkpoint_block.height()
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
                        block_hash, ctx.peer
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
                    block_hash, ctx.peer
                );
                return None;
            }
        }

        Some((state_root_vec, receipt_blame_vec, bloom_blame_vec))
    }
}

impl Request for SnapshotManifestRequest {
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
            self.snapshot_epoch_id.clone(),
        )))
    }
}
