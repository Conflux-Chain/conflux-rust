#![allow(unused)]

use crate::{
    block_data_manager::BlockExecutionResult,
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        consensus_internal::REWARD_EPOCH_COUNT,
    },
    storage::{
        storage_db::SnapshotInfo, StateRootAuxInfo, StateRootWithAuxInfo,
    },
    sync::{message::Context, state::storage::SnapshotSyncCandidate},
    verification::compute_receipts_root,
};
use cfx_types::H256;
use network::node_table::NodeId;
use primitives::{
    BlockHeaderBuilder, BlockReceipts, EpochId, EpochNumber, StateRoot,
    StorageKey, NULL_EPOCH,
};
use std::{sync::Arc, time::Instant};

pub struct SnapshotManifestManager {
    manifest_request_status: Option<(Instant, NodeId)>,
    snapshot_candidate: SnapshotSyncCandidate,
    trusted_blame_block: H256,
}

impl SnapshotManifestManager {
    pub fn new(
        snapshot_candidate: SnapshotSyncCandidate, trusted_blame_block: H256,
    ) -> Self {
        Self {
            manifest_request_status: None,
            snapshot_candidate,
            trusted_blame_block,
        }
    }

    pub fn validate_blame_states(
        ctx: &Context, snapshot_epoch_id: &H256, trusted_blame_block: &H256,
        state_root_vec: &Vec<StateRoot>, receipt_blame_vec: &Vec<H256>,
        bloom_blame_vec: &Vec<H256>,
    ) -> Option<(usize, StateRootWithAuxInfo, SnapshotInfo)>
    {
        let mut state_blame_vec = vec![];

        // these two header must exist in disk, it's safe to unwrap
        let snapshot_block_header = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(snapshot_epoch_id)
            .expect("block header must exist for snapshot to sync");
        let trusted_blame_block = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(trusted_blame_block)
            .expect("trusted_blame_block header must exist");

        // check snapshot position in `out_state_blame_vec`
        let offset = (trusted_blame_block.height()
            - (snapshot_block_header.height() + DEFERRED_STATE_EPOCH_COUNT))
            as usize;
        if offset >= state_root_vec.len() {
            warn!("validate_blame_states: not enough state_root");
            return None;
        }

        let min_vec_len = if snapshot_block_header.height() == 0 {
            trusted_blame_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - snapshot_block_header.height()
                + 1
        } else {
            trusted_blame_block.height()
                - DEFERRED_STATE_EPOCH_COUNT
                - snapshot_block_header.height()
                + REWARD_EPOCH_COUNT
        };
        let mut trusted_blocks = Vec::new();
        let mut trusted_block_height = trusted_blame_block.height();
        let mut blame_count = trusted_blame_block.blame();
        let mut block_hash = trusted_blame_block.hash();
        let mut vec_len: usize = 0;
        trusted_blocks.push(trusted_blame_block);

        // verify the length of vector.
        loop {
            vec_len += 1;
            let block = ctx
                .manager
                .graph
                .data_man
                .block_header_by_hash(&block_hash)
                .expect("block header must exist");
            // We've jump to another trusted block.
            if block.height() + blame_count as u64 + 1 == trusted_block_height {
                trusted_block_height = block.height();
                blame_count = block.blame();
                trusted_blocks.push(block.clone());
            }
            if block.height() + blame_count as u64 == trusted_block_height
                && vec_len >= min_vec_len as usize
            {
                break;
            }
            block_hash = *block.parent_hash();
        }
        // verify the length of vector
        if vec_len != state_root_vec.len() {
            warn!(
                "wrong length of state_root_vec, expected {}, but {} found",
                vec_len,
                state_root_vec.len()
            );
            return None;
        }
        // Construct out_state_blame_vec.
        state_blame_vec.clear();
        for state_root in state_root_vec {
            state_blame_vec.push(state_root.compute_state_root_hash());
        }
        let mut slice_begin = 0;
        for trusted_block in trusted_blocks {
            let slice_end = slice_begin + trusted_block.blame() as usize + 1;
            let deferred_state_root = if trusted_block.blame() == 0 {
                state_blame_vec[slice_begin].clone()
            } else {
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    state_blame_vec[slice_begin..slice_end].to_vec(),
                )
            };
            let deferred_receipts_root = if trusted_block.blame() == 0 {
                receipt_blame_vec[slice_begin].clone()
            } else {
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    receipt_blame_vec[slice_begin..slice_end].to_vec(),
                )
            };
            let deferred_logs_bloom_hash = if trusted_block.blame() == 0 {
                bloom_blame_vec[slice_begin].clone()
            } else {
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    bloom_blame_vec[slice_begin..slice_end].to_vec(),
                )
            };
            // verify `deferred_state_root`, `deferred_receipts_root` and
            // `deferred_logs_bloom_hash`
            if deferred_state_root != *trusted_block.deferred_state_root()
                || deferred_receipts_root
                    != *trusted_block.deferred_receipts_root()
                || deferred_logs_bloom_hash
                    != *trusted_block.deferred_logs_bloom_hash()
            {
                warn!("root mismatch: (state_root, receipts_root, logs_bloom_hash) \
                should be ({:?} {:?} {:?}), get ({:?} {:?} {:?})",
                      trusted_block.deferred_state_root(),
                      trusted_block.deferred_receipts_root(),
                      trusted_block.deferred_logs_bloom_hash(),
                      deferred_state_root,
                      deferred_receipts_root,
                      deferred_logs_bloom_hash,
                );
                return None;
            }
            slice_begin = slice_end;
        }

        let (parent_snapshot_epoch, pivot_chain_parts) =
            ctx.manager.graph.data_man.get_parent_epochs_for(
                snapshot_epoch_id.clone(),
                ctx.manager.graph.data_man.get_snapshot_epoch_count() as u64,
            );

        let parent_snapshot_height = if parent_snapshot_epoch == NULL_EPOCH {
            0
        } else {
            ctx.manager
                .graph
                .data_man
                .block_header_by_hash(&parent_snapshot_epoch)
                .unwrap()
                .height()
        };
        let mut snapshot_state_root = state_root_vec[offset].clone();
        let state_root_hash = state_root_vec[offset].compute_state_root_hash();
        // This delta_root is the intermediate_delta_root of the new snapshot,
        // and this field will be used to fill new state_root in
        // get_state_trees_for_next_epoch
        snapshot_state_root.intermediate_delta_root =
            state_root_vec[offset].delta_root;

        Some((
            offset,
            StateRootWithAuxInfo {
                state_root: snapshot_state_root,
                aux_info: StateRootAuxInfo {
                    // FIXME: we should not commit the EpochExecutionCommitment
                    // FIXME: for the synced snapshot because it's fake.
                    // Should be parent of parent but we don't necessarily need
                    // to know. We put the
                    // parent_snapshot_merkle_root here.
                    snapshot_epoch_id: state_root_vec[offset - 1].snapshot_root,
                    // This field will not be used
                    delta_mpt_key_padding: StorageKey::delta_mpt_padding(
                        &state_root_vec[offset].snapshot_root,
                        &state_root_vec[offset].intermediate_delta_root,
                    ),
                    intermediate_epoch_id: parent_snapshot_epoch,
                    // We don't necessarily need to know because
                    // the execution of the next epoch shifts delta MPT.
                    maybe_intermediate_mpt_key_padding: None,
                    state_root_hash,
                },
            },
            SnapshotInfo {
                serve_one_step_sync: false,
                // We need the extra -1 to get a state root that points to the
                // snapshot we want.
                merkle_root: state_root_vec[offset
                    - ctx
                        .manager
                        .graph
                        .data_man
                        .get_snapshot_blame_plus_depth()]
                .snapshot_root,
                height: snapshot_block_header.height(),
                parent_snapshot_epoch_id: parent_snapshot_epoch,
                parent_snapshot_height,
                pivot_chain_parts,
            },
        ))
    }

    pub fn validate_epoch_receipts(
        ctx: &Context, blame_vec_offset: usize, snapshot_epoch_id: &EpochId,
        receipt_blame_vec: &Vec<H256>, bloom_blame_vec: &Vec<H256>,
        block_receipts: &Vec<BlockExecutionResult>,
    ) -> Option<Vec<(H256, H256, Arc<BlockReceipts>)>>
    {
        let mut epoch_hash = snapshot_epoch_id.clone();
        let checkpoint = ctx
            .manager
            .graph
            .data_man
            .block_header_by_hash(snapshot_epoch_id)
            .expect("checkpoint header must exist");
        let epoch_receipts_count = if checkpoint.height() == 0 {
            1
        } else {
            REWARD_EPOCH_COUNT
        } as usize;
        let mut receipts_vec_offset = 0;
        let mut result = Vec::new();
        for idx in 0..epoch_receipts_count {
            let block_header = ctx
                .manager
                .graph
                .data_man
                .block_header_by_hash(&epoch_hash)
                .expect("block header must exist");
            let ordered_executable_epoch_blocks = ctx
                .manager
                .graph
                .consensus
                .get_block_hashes_by_epoch(EpochNumber::Number(
                    block_header.height(),
                ))
                .expect("ordered executable epoch blocks must exist");
            let mut epoch_receipts = Vec::new();
            for i in 0..ordered_executable_epoch_blocks.len() {
                if let Some(block_receipt) =
                    block_receipts.get(receipts_vec_offset + i)
                {
                    epoch_receipts.push(block_receipt.block_receipts.clone());
                } else {
                    // Invalid block_receipts vector length.
                    return None;
                }
            }
            let receipt_root = compute_receipts_root(&epoch_receipts);
            let logs_bloom_hash =
                BlockHeaderBuilder::compute_block_logs_bloom_hash(
                    &epoch_receipts,
                );
            if receipt_blame_vec[blame_vec_offset + idx] != receipt_root {
                debug!(
                    "wrong receipt root, expected={:?}, now={:?}",
                    receipt_blame_vec[blame_vec_offset + idx],
                    receipt_root
                );
                return None;
            }
            if bloom_blame_vec[blame_vec_offset + idx] != logs_bloom_hash {
                debug!(
                    "wrong logs bloom hash, expected={:?}, now={:?}",
                    bloom_blame_vec[blame_vec_offset + idx],
                    logs_bloom_hash
                );
                return None;
            }
            for i in 0..ordered_executable_epoch_blocks.len() {
                result.push((
                    ordered_executable_epoch_blocks[i],
                    epoch_hash,
                    epoch_receipts[i].clone(),
                ));
            }
            receipts_vec_offset += ordered_executable_epoch_blocks.len();
            epoch_hash = *block_header.parent_hash();
        }
        if receipts_vec_offset == block_receipts.len() {
            Some(result)
        } else {
            None
        }
    }
}
