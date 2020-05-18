use crate::storage::StateRootWithAuxInfo;
use cfx_types::{Bloom, H256, U256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::BlockReceipts;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::sync::Arc;

/// The number of blocks in the past of an epoch.
/// Used in evm execution.
#[derive(Clone, RlpEncodable, RlpDecodable, DeriveMallocSizeOf)]
pub struct EpochExecutionContext {
    pub start_block_number: u64,
}

/// receipts_root and logs_bloom got after an epoch is executed.
/// It is NOT deferred.
#[derive(Clone, Debug, RlpEncodable, RlpDecodable)]
pub struct EpochExecutionCommitment {
    pub state_root_with_aux_info: StateRootWithAuxInfo,
    pub receipts_root: H256,
    pub logs_bloom_hash: H256,
}

impl MallocSizeOf for EpochExecutionCommitment {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

/// `receipts` and `bloom` of a single block after execution.
/// It might change depending on this block is executed under which pivot
/// block's view.
#[derive(Clone, Debug)]
pub struct BlockExecutionResult {
    pub block_receipts: Arc<BlockReceipts>,
    pub bloom: Bloom,
}
impl MallocSizeOf for BlockExecutionResult {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.block_receipts.size_of(ops)
    }
}

impl Encodable for BlockExecutionResult {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(self.block_receipts.as_ref())
            .append(&self.bloom);
    }
}

impl Decodable for BlockExecutionResult {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(BlockExecutionResult {
            block_receipts: Arc::new(rlp.val_at(0)?),
            bloom: rlp.val_at(1)?,
        })
    }
}

#[derive(RlpEncodable, RlpDecodable, Clone, Copy, Debug, DeriveMallocSizeOf)]
pub struct BlockRewardResult {
    pub total_reward: U256,
    pub base_reward: U256,
    pub tx_fee: U256,
}

impl Default for BlockRewardResult {
    fn default() -> Self {
        BlockRewardResult {
            total_reward: U256::from(0),
            base_reward: U256::from(0),
            tx_fee: U256::from(0),
        }
    }
}

/// The structure to maintain the `BlockExecutedResult` of blocks under
/// different views.
///
/// Note that in database only the results corresponding to the current pivot
/// chain exist. This multi-version receipts are only maintained in memory and
/// will be garbage collected.
type EpochIndex = H256;
#[derive(Debug, DeriveMallocSizeOf)]
pub struct BlockExecutionResultWithEpoch(
    pub EpochIndex,
    pub BlockExecutionResult,
);
#[derive(Default, Debug)]
pub struct BlockReceiptsInfo {
    execution_info_with_epoch: Vec<BlockExecutionResultWithEpoch>,
    // The current pivot epoch that this block is executed.
    // This should be consistent with the epoch hash in database.
    pivot_epoch: EpochIndex,
}

impl BlockReceiptsInfo {
    /// Return None if we do not have a corresponding ExecutionResult in the
    /// given `epoch`. Return `(ExecutionResult, is_on_pivot)` otherwise.
    pub fn get_receipts_at_epoch(
        &self, epoch: &EpochIndex,
    ) -> Option<(BlockExecutionResult, bool)> {
        for BlockExecutionResultWithEpoch(e_id, receipts) in
            &self.execution_info_with_epoch
        {
            if *e_id == *epoch {
                return Some((receipts.clone(), epoch == &self.pivot_epoch));
            }
        }
        None
    }

    pub fn set_pivot_hash(&mut self, epoch: EpochIndex) {
        self.pivot_epoch = epoch;
    }

    /// Insert the tx fee when the block is included in epoch `epoch`
    pub fn insert_receipts_at_epoch(
        &mut self, epoch: &EpochIndex, receipts: BlockExecutionResult,
    ) {
        // If it's inserted before, we do not need to push a duplicated entry.
        if self.get_receipts_at_epoch(epoch).is_none() {
            self.execution_info_with_epoch
                .push(BlockExecutionResultWithEpoch(*epoch, receipts));
        }
        self.pivot_epoch = *epoch;
    }

    /// Only keep the receipts in the given `epoch`
    /// Called after we process rewards, and other fees will not be used w.h.p.
    pub fn retain_epoch(&mut self, epoch: &EpochIndex) {
        self.execution_info_with_epoch
            .retain(|BlockExecutionResultWithEpoch(e_id, _)| *e_id == *epoch);
        self.pivot_epoch = *epoch;
    }
}

impl MallocSizeOf for BlockReceiptsInfo {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.execution_info_with_epoch.size_of(ops)
    }
}

impl Encodable for BlockExecutionResultWithEpoch {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2).append(&self.0).append(&self.1);
    }
}

impl Decodable for BlockExecutionResultWithEpoch {
    fn decode(
        rlp: &Rlp,
    ) -> Result<BlockExecutionResultWithEpoch, DecoderError> {
        Ok(BlockExecutionResultWithEpoch(
            rlp.val_at(0)?,
            rlp.val_at(1)?,
        ))
    }
}

/// The local information about a block. It is NOT consistent across different
/// nodes.
#[derive(Copy, Clone, DeriveMallocSizeOf)]
pub struct LocalBlockInfo {
    status: BlockStatus,
    enter_consensus_seq_num: u64,
    pub instance_id: u64,
}

impl LocalBlockInfo {
    pub fn new(status: BlockStatus, seq_num: u64, instance_id: u64) -> Self {
        LocalBlockInfo {
            status,
            enter_consensus_seq_num: seq_num,
            instance_id,
        }
    }

    pub fn get_status(&self) -> BlockStatus { self.status }

    pub fn get_seq_num(&self) -> u64 { self.enter_consensus_seq_num }

    pub fn get_instance_id(&self) -> u64 { self.instance_id }
}

impl Encodable for LocalBlockInfo {
    fn rlp_append(&self, stream: &mut RlpStream) {
        let status = self.status.to_db_status();
        stream
            .begin_list(3)
            .append(&status)
            .append(&self.enter_consensus_seq_num)
            .append(&self.instance_id);
    }
}

impl Decodable for LocalBlockInfo {
    fn decode(rlp: &Rlp) -> Result<LocalBlockInfo, DecoderError> {
        let status: u8 = rlp.val_at(0)?;
        Ok(LocalBlockInfo {
            status: BlockStatus::from_db_status(status),
            enter_consensus_seq_num: rlp.val_at(1)?,
            instance_id: rlp.val_at(2)?,
        })
    }
}

/// The validity status of a block. If a block's status among all honest nodes
/// is guaranteed to have no conflict, which means if some honest nodes think a
/// block is not `Pending`, their decision will be the same status.
#[derive(Copy, Clone, PartialEq, DeriveMallocSizeOf)]
pub enum BlockStatus {
    Valid = 0,
    Invalid = 1,
    PartialInvalid = 2,
    Pending = 3,
}

impl BlockStatus {
    fn from_db_status(db_status: u8) -> Self {
        match db_status {
            0 => BlockStatus::Valid,
            1 => BlockStatus::Invalid,
            2 => BlockStatus::PartialInvalid,
            3 => BlockStatus::Pending,
            _ => panic!("Read unknown block status from db"),
        }
    }

    pub fn to_db_status(&self) -> u8 { *self as u8 }
}

/// The checkpoint information stored in the database
#[derive(RlpEncodable, RlpDecodable, Clone)]
pub struct CheckpointHashes {
    pub prev_hash: H256,
    pub cur_hash: H256,
}

impl CheckpointHashes {
    pub fn new(prev_hash: H256, cur_hash: H256) -> Self {
        Self {
            prev_hash,
            cur_hash,
        }
    }
}
