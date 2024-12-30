use cfx_execute_helper::exec_tracer::BlockExecTraces;
use cfx_internal_common::{
    impl_db_encoding_as_rlp, DatabaseDecodable, DatabaseEncodable,
};
use cfx_types::{Address, Bloom, H256, U256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::BlockReceipts;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use smart_default::SmartDefault;
use std::sync::Arc;

/// The start block number of an epoch. It equals to the past executed number of
/// blocks in the previous epoch + 1. For the true genesis, it equals 0.
/// Used in evm execution.
#[derive(Clone, RlpEncodable, RlpDecodable, DeriveMallocSizeOf)]
pub struct EpochExecutionContext {
    pub start_block_number: u64,
}

/// `receipts` and `bloom` of a single block after execution.
/// It might change depending on this block is executed under which pivot
/// block's view.
#[derive(Clone, Debug)]
pub struct BlockExecutionResult {
    // FIXME: why it's an Arc.
    pub block_receipts: Arc<BlockReceipts>,
    pub bloom: Bloom,
}
impl MallocSizeOf for BlockExecutionResult {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.block_receipts.size_of(ops)
    }
}

// FIXME: RlpEncodable.
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

#[derive(
    RlpEncodable, RlpDecodable, Clone, Copy, Debug, DeriveMallocSizeOf,
)]
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

pub type BlockRewardsInfo = BlockDataWithMultiVersion<H256, BlockRewardResult>;

#[derive(Clone, Debug, DeriveMallocSizeOf)]
pub struct DataVersionTuple<Version, T>(pub Version, pub T);

pub type BlockExecutionResultWithEpoch =
    DataVersionTuple<H256, BlockExecutionResult>;
pub type BlockTracesWithEpoch = DataVersionTuple<H256, BlockExecTraces>;
pub type BlockReceiptsInfo =
    BlockDataWithMultiVersion<H256, BlockExecutionResult>;
pub type BlockTracesInfo = BlockDataWithMultiVersion<H256, BlockExecTraces>;

impl BlockExecutionResultWithEpoch {
    pub fn new(pivot_hash: H256, receipts: BlockExecutionResult) -> Self {
        DataVersionTuple(pivot_hash, receipts)
    }
}

impl BlockTracesWithEpoch {
    pub fn new(pivot_hash: H256, traces: BlockExecTraces) -> Self {
        DataVersionTuple(pivot_hash, traces)
    }
}

/// The structure to maintain block data under different views.
///
/// Note that in database only the data corresponding to the current pivot
/// chain exist. This multi-version version are only maintained in memory and
/// will be garbage collected. When `insert_current_data()` is called, we always
/// update the version in DB to the current version.
/// If there is no garbage-collection, this guarantees that the version in DB is
/// the latest, and the in-memory version is EVENTUALLY consistent with the one
/// in DB.
///
/// FIXME: There is a rare case to cause inconsistency with GC:
/// Assume a thread T1 is writing the latest data and T2 is answering
/// RPC requests, and the in-memory data have been garbage collected.
///
/// T2 reads old data from DB-> T1 writes new data to DB -> T1 writes new data
/// to memory -> in-memory data are garbage collected again -> T2 writes old
/// data to memory successfully with `insert_data()`
///
/// Now the data in DB are new, but the ones in memory are old.
/// If we lock the in-memory structure before reading from DB, or we do not
/// update the in-memory data with the one from DB, this inconsistency can be
/// eliminated, but the performance will be affected.
#[derive(Debug, SmartDefault)]
pub struct BlockDataWithMultiVersion<Version, T> {
    data_version_tuple_array: Vec<DataVersionTuple<Version, T>>,
    // The current pivot epoch that this block is executed.
    // This should be consistent with the epoch hash in database.
    current_version: Option<Version>,
}

impl<Version: Copy + Eq + PartialEq, T: Clone>
    BlockDataWithMultiVersion<Version, T>
{
    /// Return None if we do not have a corresponding data in the
    /// given `version`. Return `(data, is_current)` otherwise.
    pub fn get_data_at_version(&self, version: &Version) -> Option<(T, bool)> {
        self.current_version.as_ref().and_then(|current_version| {
            for DataVersionTuple(e_id, data) in &self.data_version_tuple_array {
                if *e_id == *version {
                    return Some((data.clone(), version == current_version));
                }
            }
            None
        })
    }

    pub fn get_current_data(&self) -> Option<DataVersionTuple<Version, T>> {
        self.current_version.as_ref().map(|current_version| {
            for versioned_data in &self.data_version_tuple_array {
                if versioned_data.0 == *current_version {
                    return versioned_data.clone();
                }
            }
            unreachable!("The current data should exist")
        })
    }

    pub fn set_current_version(&mut self, version: Version) {
        self.current_version = Some(version);
    }

    /// Insert the latest data with its version.
    /// This should be called after we update the version in the database to
    /// ensure consistency.
    pub fn insert_current_data(&mut self, version: &Version, data: T) {
        // If it's inserted before, we do not need to push a duplicated entry.
        if self.get_data_at_version(version).is_none() {
            self.data_version_tuple_array
                .push(DataVersionTuple(*version, data));
        }
        self.current_version = Some(*version);
    }

    /// Insert the data with its version and update the current version if it's
    /// not set. This is used when `version` is not guaranteed to be the
    /// latest.
    pub fn insert_data(&mut self, version: &Version, data: T) {
        // If it's inserted before, we do not need to push a duplicated entry.
        if self.get_data_at_version(version).is_none() {
            self.data_version_tuple_array
                .push(DataVersionTuple(*version, data));
        }
        if self.current_version.is_none() {
            self.current_version = Some(*version);
        }
    }

    /// Only keep the data in the given `version`.
    /// Called when the data on other versions are not likely to be needed.
    pub fn retain_version(&mut self, version: &Version) {
        self.data_version_tuple_array
            .retain(|DataVersionTuple(e_id, _)| e_id == version);
        self.current_version = Some(*version);
    }
}

impl<VersionIndex: MallocSizeOf, T: MallocSizeOf> MallocSizeOf
    for BlockDataWithMultiVersion<VersionIndex, T>
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.data_version_tuple_array.size_of(ops)
    }
}

impl<Version: Encodable, T: Encodable> Encodable
    for DataVersionTuple<Version, T>
{
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2).append(&self.0).append(&self.1);
    }
}

impl<Version: Decodable, T: Decodable> Decodable
    for DataVersionTuple<Version, T>
{
    fn decode(rlp: &Rlp) -> Result<DataVersionTuple<Version, T>, DecoderError> {
        Ok(DataVersionTuple(rlp.val_at(0)?, rlp.val_at(1)?))
    }
}

impl<Version: Encodable, T: Encodable> DatabaseEncodable
    for DataVersionTuple<Version, T>
{
    fn db_encode(&self) -> Vec<u8> { rlp::encode(self) }
}

impl<Version: Decodable, T: Decodable> DatabaseDecodable
    for DataVersionTuple<Version, T>
{
    fn db_decode(bytes: &[u8]) -> Result<Self, DecoderError> {
        rlp::decode(bytes)
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

/// Verified roots of blamed headers stored on disk on light nodes.
#[derive(Clone, Debug, RlpEncodable, RlpDecodable)]
pub struct BlamedHeaderVerifiedRoots {
    pub deferred_state_root: H256,
    pub deferred_receipts_root: H256,
    pub deferred_logs_bloom_hash: H256,
}

impl MallocSizeOf for BlamedHeaderVerifiedRoots {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

#[derive(Clone, Debug, RlpEncodable, RlpDecodable)]
pub struct PosRewardForAccount {
    pub address: Address,
    pub pos_identifier: H256,
    pub reward: U256,
}

#[derive(Clone, Debug, RlpEncodable, RlpDecodable)]
pub struct PosRewardInfo {
    pub account_rewards: Vec<PosRewardForAccount>,
    /// The PoW epoch hash where the reward is distributed in its execution.
    pub execution_epoch_hash: H256,
}

impl PosRewardInfo {
    pub fn new(
        account_reward_list: Vec<(Address, H256, U256)>,
        execution_epoch_hash: H256,
    ) -> Self {
        let account_rewards = account_reward_list
            .into_iter()
            .map(|(address, pos_identifier, reward)| PosRewardForAccount {
                address,
                pos_identifier,
                reward,
            })
            .collect();
        Self {
            account_rewards,
            execution_epoch_hash,
        }
    }
}

pub fn db_encode_list<T>(list: &[T]) -> Vec<u8>
where T: DatabaseEncodable {
    let mut rlp_stream = RlpStream::new();
    rlp_stream.begin_list(list.len());
    for e in list {
        rlp_stream.append_raw(&e.db_encode(), 1);
    }
    rlp_stream.drain()
}

pub fn db_decode_list<T>(bytes: &[u8]) -> Result<Vec<T>, DecoderError>
where T: DatabaseDecodable {
    let rlp_encoded = Rlp::new(bytes);
    let mut list = Vec::new();
    for e in rlp_encoded.iter() {
        list.push(T::db_decode(e.as_raw())?);
    }
    Ok(list)
}

impl_db_encoding_as_rlp!(BlockExecutionResult);
impl_db_encoding_as_rlp!(LocalBlockInfo);
impl_db_encoding_as_rlp!(CheckpointHashes);
impl_db_encoding_as_rlp!(EpochExecutionContext);
impl_db_encoding_as_rlp!(BlockRewardResult);
impl_db_encoding_as_rlp!(BlamedHeaderVerifiedRoots);
impl_db_encoding_as_rlp!(PosRewardInfo);
