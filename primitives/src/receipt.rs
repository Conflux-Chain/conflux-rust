// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::log_entry::LogEntry;
use cfx_types::{Address, Bloom, U256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
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
#[derive(Debug, Clone, PartialEq, Eq, RlpDecodable, RlpEncodable)]
pub struct Receipt {
    /// The total gas used in the block following execution of the transaction.
    pub gas_used: U256,
    /// The OR-wide combination of all logs' blooms for this transaction.
    pub log_bloom: Bloom,
    /// The logs stemming from this transaction.
    pub logs: Vec<LogEntry>,
    /// Transaction outcome.
    pub outcome_status: u8,
    pub storage_collateralized: Vec<StorageChange>,
    pub storage_released: Vec<StorageChange>,
}

impl Receipt {
    pub fn new(
        outcome: u8, gas_used: U256, logs: Vec<LogEntry>,
        storage_collateralized: Vec<StorageChange>,
        storage_released: Vec<StorageChange>,
    ) -> Self
    {
        Self {
            gas_used,
            log_bloom: logs.iter().fold(Bloom::default(), |mut b, l| {
                b.accrue_bloom(&l.bloom());
                b
            }),
            logs,
            outcome_status: outcome,
            storage_collateralized,
            storage_released,
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
    /// This is the amount of secondary reward this block.
    pub secondary_reward: U256,
}

impl MallocSizeOf for BlockReceipts {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.receipts.size_of(ops)
    }
}
