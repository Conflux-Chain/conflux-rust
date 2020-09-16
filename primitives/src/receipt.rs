// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::log_entry::LogEntry;
use cfx_types::{Address, Bloom, U256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rlp::{
    Decodable as RlpDecodable, DecoderError, Encodable as RlpEncodable, Rlp,
    RlpStream,
};
use rlp_derive::{RlpDecodable, RlpEncodable};

pub const TRANSACTION_OUTCOME_SUCCESS: u8 = 0;
pub const TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING: u8 = 1; // gas fee charged
pub const TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING: u8 = 2; // no gas fee charged

#[derive(Debug, Clone, PartialEq, Eq, RlpDecodable, RlpEncodable)]
pub struct StorageChange {
    pub address: Address,
    /// Number of bytes.
    pub amount: u64,
}

/// Information describing execution of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The total gas used (not gas charged) in the block following execution
    /// of the transaction.
    pub accumulated_gas_used: U256,
    /// The gas fee charged for transaction execution.
    pub gas_fee: U256,
    /// The designated account to bear the gas fee, if any.
    pub gas_sponsor_paid: bool,
    /// The OR-wide combination of all logs' blooms for this transaction.
    pub log_bloom: Bloom,
    /// The logs stemming from this transaction.
    pub logs: Vec<LogEntry>,
    /// Transaction outcome.
    pub outcome_status: u8,
    /// The designated account to bear the storage fee, if any.
    pub storage_sponsor_paid: bool,
    pub storage_collateralized: Vec<StorageChange>,
    pub storage_released: Vec<StorageChange>,

    /// Error message (Non-authenticated field & not compiled in RLP)
    /// Note: it is no guarantee that the `error_message` is always available.
    pub error_message: String,
}

impl Receipt {
    pub fn new(
        outcome: u8, accumulated_gas_used: U256, gas_fee: U256,
        gas_sponsor_paid: bool, logs: Vec<LogEntry>,
        storage_sponsor_paid: bool, storage_collateralized: Vec<StorageChange>,
        storage_released: Vec<StorageChange>, error_message: String,
    ) -> Self
    {
        Self {
            accumulated_gas_used,
            gas_fee,
            gas_sponsor_paid,
            log_bloom: logs.iter().fold(Bloom::default(), |mut b, l| {
                b.accrue_bloom(&l.bloom());
                b
            }),
            logs,
            outcome_status: outcome,
            storage_sponsor_paid,
            storage_collateralized,
            storage_released,
            error_message,
        }
    }
}

impl MallocSizeOf for StorageChange {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl MallocSizeOf for Receipt {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.logs.size_of(ops)
            + self.storage_released.size_of(ops)
            + self.storage_released.size_of(ops)
    }
}

/// Information describing execution of a block.
#[derive(Debug, Clone, PartialEq, Eq, RlpDecodable, RlpEncodable)]
pub struct BlockReceipts {
    /// This is the receipts of transaction execution in this block.
    pub receipts: Vec<Receipt>,
    // FIXME:
    //   This field doesn't belong to receipts root calculation.
    /// This is the amount of secondary reward this block.
    pub secondary_reward: U256,
}

impl BlockReceipts {
    #[inline]
    pub fn get_error_messages<'a>(&'a self) -> Vec<&'a String> {
        self.receipts
            .iter()
            .map(|x| &x.error_message)
            .collect::<Vec<&'a String>>()
    }

    #[inline]
    // The passed in messages must have the same length as block_receipts
    pub fn set_error_messages(&mut self, messages: Vec<String>) {
        self.receipts
            .iter_mut()
            .zip(messages)
            .for_each(|(x, msg)| x.error_message = msg);
    }
}

impl MallocSizeOf for BlockReceipts {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.receipts.size_of(ops)
    }
}

impl RlpEncodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(9)
            .append(&self.accumulated_gas_used)
            .append(&self.gas_fee)
            .append(&self.gas_sponsor_paid)
            .append(&self.log_bloom)
            .append_list(&self.logs)
            .append(&self.outcome_status)
            .append(&self.storage_sponsor_paid)
            .append_list(&self.storage_collateralized)
            .append_list(&self.storage_released);
    }
}

impl RlpDecodable for Receipt {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Receipt {
            accumulated_gas_used: rlp.val_at(0)?,
            gas_fee: rlp.val_at(1)?,
            gas_sponsor_paid: rlp.val_at(2)?,
            log_bloom: rlp.val_at(3)?,
            logs: rlp.list_at(4)?,
            outcome_status: rlp.val_at(5)?,
            storage_sponsor_paid: rlp.val_at(6)?,
            storage_collateralized: rlp.list_at(7)?,
            storage_released: rlp.list_at(8)?,
            error_message: "".to_string(),
        })
    }
}
