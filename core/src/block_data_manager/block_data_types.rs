use cfx_types::{Bloom, H256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use primitives::Receipt;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::sync::Arc;

/// The number of blocks in the past of an epoch.
/// Used in evm execution.
#[derive(Clone)]
pub struct EpochExecutionContext {
    pub start_block_number: u64,
}

/// receipts_root and logs_bloom got after an epoch is executed.
/// It is NOT deferred.
#[derive(Clone)]
pub struct EpochExecutionCommitments {
    pub receipts_root: H256,
    pub logs_bloom_hash: H256,
}

/// The DEFERRED state_root, receipt_root, and logs_bloom of an block.
/// They may not be the ones in the block header which is the hash of that of
/// all blamed block headers if `blame` is not 0.
#[derive(Clone, RlpEncodable, RlpDecodable, Default)]
pub struct ConsensusGraphExecutionInfo {
    pub original_deferred_state_root: H256,
    pub original_deferred_receipt_root: H256,
    pub original_deferred_logs_bloom_hash: H256,
}

/// `receipts` and `bloom` of a single block after execution.
/// It might change depending on this block is executed under which pivot
/// block's view.
#[derive(Clone, Debug)]
pub struct BlockExecutedResult {
    pub receipts: Arc<Vec<Receipt>>,
    pub bloom: Bloom,
}
impl MallocSizeOf for BlockExecutedResult {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.receipts.size_of(ops)
    }
}
type EpochIndex = H256;

/// The structure to maintain the `BlockExecutedResult` of blocks under
/// different views.
///
/// Note that in database only the results corresponding to the current pivot
/// chain exist. This multi-version receipts are only maintained in memory and
/// will be garbage collected.
#[derive(Default, Debug)]
pub struct BlockReceiptsInfo {
    info_with_epoch: Vec<(EpochIndex, BlockExecutedResult)>,
}

impl MallocSizeOf for BlockReceiptsInfo {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.info_with_epoch.size_of(ops)
    }
}

impl BlockReceiptsInfo {
    /// `epoch` is the index of the epoch id in consensus arena
    pub fn get_receipts_at_epoch(
        &self, epoch: &EpochIndex,
    ) -> Option<BlockExecutedResult> {
        for (e_id, receipts) in &self.info_with_epoch {
            if *e_id == *epoch {
                return Some(receipts.clone());
            }
        }
        None
    }

    /// Insert the tx fee when the block is included in epoch `epoch`
    pub fn insert_receipts_at_epoch(
        &mut self, epoch: &EpochIndex, receipts: BlockExecutedResult,
    ) {
        // If it's inserted before, the fee must be the same, so we do not add
        // duplicate entry
        if self.get_receipts_at_epoch(epoch).is_none() {
            self.info_with_epoch.push((*epoch, receipts));
        }
    }

    /// Only keep the tx fee in the given `epoch`
    /// Called after we process rewards, and other fees will not be used w.h.p.
    pub fn retain_epoch(&mut self, epoch: &EpochIndex) {
        self.info_with_epoch.retain(|(e_id, _)| *e_id == *epoch);
    }
}

/// The local information about a block. It is NOT consistent across different
/// nodes.
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone, PartialEq)]
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

    fn to_db_status(&self) -> u8 { *self as u8 }
}
