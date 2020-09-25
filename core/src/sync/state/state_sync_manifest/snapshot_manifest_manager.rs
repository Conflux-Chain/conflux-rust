#![allow(unused)]

use crate::{
    block_data_manager::BlockExecutionResult,
    message::NetworkContext,
    sync::{
        error::{Error, ErrorKind},
        message::{
            msgid, Context, SnapshotManifestRequest, SnapshotManifestResponse,
        },
        state::storage::SnapshotSyncCandidate,
        synchronization_state::PeerFilter,
        SynchronizationProtocolHandler,
    },
    verification::compute_receipts_root,
};
use cfx_internal_common::{StateRootAuxInfo, StateRootWithAuxInfo};
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    consensus_internal::REWARD_EPOCH_COUNT,
};
use cfx_storage::{storage_db::SnapshotInfo, TrieProof};
use cfx_types::H256;
use network::node_table::NodeId;
use primitives::{
    BlockHeaderBuilder, BlockReceipts, EpochId, EpochNumber, StateRoot,
    StorageKey, NULL_EPOCH,
};
use rand::{seq::SliceRandom, thread_rng};
use std::{
    collections::HashSet,
    fmt::{Debug, Formatter},
    sync::Arc,
    time::{Duration, Instant},
};

pub struct SnapshotManifestManager {
    manifest_request_status: Option<(Instant, NodeId)>,
    pub snapshot_candidate: SnapshotSyncCandidate,
    trusted_blame_block: H256,
    pub active_peers: HashSet<NodeId>,

    pub chunk_boundaries: Vec<Vec<u8>>,
    pub chunk_boundary_proofs: Vec<TrieProof>,

    related_data: Option<RelatedData>,
    config: SnapshotManifestConfig,
}

#[derive(Clone)]
pub struct RelatedData {
    /// State root verified by blame.
    pub true_state_root_by_blame_info: StateRootWithAuxInfo,
    /// Point to the corresponding entry to the snapshot in the blame vectors.
    pub blame_vec_offset: usize,
    pub receipt_blame_vec: Vec<H256>,
    pub bloom_blame_vec: Vec<H256>,
    pub epoch_receipts: Vec<(H256, H256, Arc<BlockReceipts>)>,
    pub snapshot_info: SnapshotInfo,
}

impl SnapshotManifestManager {
    pub fn new_and_start(
        snapshot_candidate: SnapshotSyncCandidate, trusted_blame_block: H256,
        active_peers: HashSet<NodeId>, config: SnapshotManifestConfig,
        io: &dyn NetworkContext, sync_handler: &SynchronizationProtocolHandler,
    ) -> Self
    {
        let mut manager = Self {
            manifest_request_status: None,
            snapshot_candidate,
            trusted_blame_block,
            active_peers,
            chunk_boundaries: vec![],
            chunk_boundary_proofs: vec![],
            related_data: None,
            config,
        };
        manager.request_manifest(io, sync_handler, None);
        manager
    }

    pub fn handle_snapshot_manifest_response(
        &mut self, ctx: &Context, response: SnapshotManifestResponse,
        request: &SnapshotManifestRequest,
    ) -> Result<Option<RelatedData>, Error>
    {
        match self
            .handle_snapshot_manifest_response_impl(ctx, response, request)
        {
            Ok(r) => Ok(r),
            Err(e) => {
                self.note_failure(&ctx.node_id);
                Err(e)
            }
        }
    }

    fn handle_snapshot_manifest_response_impl(
        &mut self, ctx: &Context, response: SnapshotManifestResponse,
        request: &SnapshotManifestRequest,
    ) -> Result<Option<RelatedData>, Error>
    {
        // new era started
        if request.snapshot_to_sync != self.snapshot_candidate {
            info!(
                "The received snapshot manifest doesn't match the current snapshot_candidate,\
                 current snapshot_candidate = {:?}, requested sync candidate = {:?}",
                self.snapshot_candidate,
                request.snapshot_to_sync);
            return Ok(None);
        }

        info!(
            "Snapshot manifest received, checkpoint = {:?}, chunk_boundaries.len()={}, \
            start={:?}, next={:?}",
            self.snapshot_candidate, response.manifest.chunk_boundaries.len(),
            request.start_chunk, response.manifest.next
        );

        // validate blame state if requested
        if request.is_initial_request() {
            if !self.chunk_boundaries.is_empty() {
                bail!(ErrorKind::InvalidSnapshotManifest(
                    "Initial manifest is not expected".into(),
                ));
            }
            let (blame_vec_offset, state_root_with_aux_info, snapshot_info) =
                match Self::validate_blame_states(
                    ctx,
                    self.snapshot_candidate.get_snapshot_epoch_id(),
                    &self.trusted_blame_block,
                    &response.state_root_vec,
                    &response.receipt_blame_vec,
                    &response.bloom_blame_vec,
                ) {
                    Some(info_tuple) => info_tuple,
                    None => {
                        warn!("failed to validate the blame state, re-sync manifest from other peer");
                        self.resync_manifest(ctx);
                        bail!(ErrorKind::InvalidSnapshotManifest(
                            "invalid blame state in manifest".into(),
                        ));
                    }
                };

            let epoch_receipts =
                match SnapshotManifestManager::validate_epoch_receipts(
                    ctx,
                    blame_vec_offset,
                    self.snapshot_candidate.get_snapshot_epoch_id(),
                    &response.receipt_blame_vec,
                    &response.bloom_blame_vec,
                    &response.block_receipts,
                ) {
                    Some(epoch_receipts) => epoch_receipts,
                    None => {
                        warn!("failed to validate the epoch receipts, re-sync manifest from other peer");
                        self.resync_manifest(ctx);
                        bail!(ErrorKind::InvalidSnapshotManifest(
                            "invalid epoch receipts in manifest".into(),
                        ));
                    }
                };

            // Check proofs for keys.
            if let Err(e) =
                response.manifest.validate(&snapshot_info.merkle_root)
            {
                warn!("failed to validate snapshot manifest, error = {:?}", e);
                bail!(ErrorKind::InvalidSnapshotManifest(
                    "invalid chunk proofs in manifest".into(),
                ));
            }
            self.related_data = Some(RelatedData {
                true_state_root_by_blame_info: state_root_with_aux_info,
                blame_vec_offset,
                receipt_blame_vec: response.receipt_blame_vec,
                bloom_blame_vec: response.bloom_blame_vec,
                epoch_receipts,
                snapshot_info,
            });
        } else {
            if self.chunk_boundaries.is_empty() {
                bail!(ErrorKind::InvalidSnapshotManifest(
                    "Non-initial manifest is not expected".into()
                ));
            }
            debug_assert_eq!(
                request.start_chunk.as_ref(),
                self.chunk_boundaries.last()
            );
            if let Some(related_data) = &self.related_data {
                // Check proofs for keys.
                if let Err(e) = response
                    .manifest
                    .validate(&related_data.snapshot_info.merkle_root)
                {
                    warn!(
                        "failed to validate snapshot manifest, error = {:?}",
                        e
                    );
                    bail!(ErrorKind::InvalidSnapshotManifest(
                        "invalid chunk proofs in manifest".into(),
                    ));
                }
            }
        }
        // The first element is `start_key` and overlaps with the previous
        // manifest.
        self.chunk_boundaries
            .extend_from_slice(&response.manifest.chunk_boundaries);
        self.chunk_boundary_proofs
            .extend_from_slice(&response.manifest.chunk_boundary_proofs);
        if response.manifest.next.is_none() {
            return Ok(self.related_data.clone());
        } else {
            self.request_manifest(ctx.io, ctx.manager, response.manifest.next);
        }
        Ok(None)
    }

    /// request manifest from random peer
    pub fn request_manifest(
        &mut self, io: &dyn NetworkContext,
        sync_handler: &SynchronizationProtocolHandler,
        start_chunk: Option<Vec<u8>>,
    )
    {
        let maybe_trusted_blame_block = if start_chunk.is_none() {
            Some(self.trusted_blame_block.clone())
        } else {
            None
        };
        let request = SnapshotManifestRequest::new(
            // Safe to unwrap since it's guaranteed to be Some(..)
            self.snapshot_candidate.clone(),
            maybe_trusted_blame_block,
            start_chunk,
        );

        let available_peers = PeerFilter::new(msgid::GET_SNAPSHOT_MANIFEST)
            .choose_from(&self.active_peers)
            .select_all(&sync_handler.syn);
        let maybe_peer = available_peers.choose(&mut thread_rng()).map(|p| *p);
        if let Some(peer) = maybe_peer {
            self.manifest_request_status = Some((Instant::now(), peer));
            sync_handler.request_manager.request_with_delay(
                io,
                Box::new(request),
                Some(peer),
                None,
            );
        }
    }

    fn resync_manifest(&mut self, ctx: &Context) {
        self.request_manifest(
            ctx.io,
            ctx.manager,
            self.chunk_boundaries.last().cloned(),
        );
    }

    pub fn check_timeout(&mut self, ctx: &Context) {
        if let Some((manifest_start_time, peer)) = &self.manifest_request_status
        {
            if manifest_start_time.elapsed()
                > self.config.manifest_request_timeout
            {
                self.active_peers.remove(peer);
                self.manifest_request_status = None;
                self.resync_manifest(ctx);
            }
        }
    }

    pub fn is_inactive(&self) -> bool { self.active_peers.is_empty() }

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
                snapshot_info_kept_to_provide_sync: false,
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

    pub fn on_peer_disconnected(&mut self, peer: &NodeId) {
        self.active_peers.remove(peer);
    }

    fn note_failure(&mut self, node_id: &NodeId) {
        self.active_peers.remove(node_id);
    }
}

impl Debug for SnapshotManifestManager {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "(request_status = {:?}, candidate={:?} active_peers: {})",
            self.manifest_request_status,
            self.snapshot_candidate,
            self.active_peers.len(),
        )
    }
}

pub struct SnapshotManifestConfig {
    pub manifest_request_timeout: Duration,
}
