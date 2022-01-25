// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::log_entry::LogEntry;
use cfx_types::{Address, Bloom, Space, U256, U64};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

pub const TRANSACTION_OUTCOME_SUCCESS: u8 = 0;
pub const TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING: u8 = 1; // gas fee charged
pub const TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING: u8 = 2; // no gas fee charged

pub const EVM_SPACE_FAIL: u8 = 0;
pub const EVM_SPACE_SUCCESS: u8 = 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionOutcome {
    Success = 0,
    Failure = 1,
    Skipped = 2,
}

impl TransactionOutcome {
    fn into_u8(&self) -> u8 {
        match self {
            TransactionOutcome::Success => 0,
            TransactionOutcome::Failure => 1,
            TransactionOutcome::Skipped => 2,
        }
    }
}

impl Encodable for TransactionOutcome {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_internal(&self.into_u8());
    }
}

impl Decodable for TransactionOutcome {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.as_val::<u8>()? {
            0 => Ok(TransactionOutcome::Success),
            1 => Ok(TransactionOutcome::Failure),
            2 => Ok(TransactionOutcome::Skipped),
            _ => Err(DecoderError::Custom("Unrecognized outcome status")),
        }
    }
}

impl Default for TransactionOutcome {
    fn default() -> Self { TransactionOutcome::Success }
}

impl TransactionOutcome {
    pub fn in_space(&self, space: Space) -> u8 {
        match (space, self) {
            // Conflux
            (Space::Native, TransactionOutcome::Success) => {
                TRANSACTION_OUTCOME_SUCCESS
            }
            (Space::Native, TransactionOutcome::Failure) => {
                TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING
            }
            (Space::Native, TransactionOutcome::Skipped) => {
                TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING
            }

            // EVM
            (Space::Ethereum, TransactionOutcome::Success) => EVM_SPACE_SUCCESS,
            (Space::Ethereum, TransactionOutcome::Failure) => EVM_SPACE_FAIL,
            (Space::Ethereum, TransactionOutcome::Skipped) => 0xff,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, RlpDecodable, RlpEncodable)]
pub struct StorageChange {
    pub address: Address,
    /// Number of storage collateral units to deposit / refund (absolute
    /// value).
    pub collaterals: U64,
}

/// Information describing execution of a transaction.
#[derive(Debug, Clone, PartialEq, Eq, RlpDecodable, RlpEncodable)]
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
    pub outcome_status: TransactionOutcome,
    /// The designated account to bear the storage fee, if any.
    pub storage_sponsor_paid: bool,
    pub storage_collateralized: Vec<StorageChange>,
    pub storage_released: Vec<StorageChange>,
}

impl Receipt {
    pub fn new(
        outcome: TransactionOutcome, accumulated_gas_used: U256, gas_fee: U256,
        gas_sponsor_paid: bool, logs: Vec<LogEntry>, log_bloom: Bloom,
        storage_sponsor_paid: bool, storage_collateralized: Vec<StorageChange>,
        storage_released: Vec<StorageChange>,
    ) -> Self
    {
        Self {
            accumulated_gas_used,
            gas_fee,
            gas_sponsor_paid,
            log_bloom,
            logs,
            outcome_status: outcome,
            storage_sponsor_paid,
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
    // FIXME:
    //   These fields below do not belong to receipts root calculation.
    pub block_number: u64,
    /// This is the amount of secondary reward this block.
    pub secondary_reward: U256,
    /// The error messages for each transaction. A successful transaction has
    /// empty error_messages.
    pub tx_execution_error_messages: Vec<String>,
}

impl MallocSizeOf for BlockReceipts {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.receipts.size_of(ops)
    }
}

#[test]
fn test_transaction_outcome_rlp() {
    assert_eq!(rlp::encode(&TransactionOutcome::Success), rlp::encode(&0u8));
    assert_eq!(rlp::encode(&TransactionOutcome::Failure), rlp::encode(&1u8));
    assert_eq!(rlp::encode(&TransactionOutcome::Skipped), rlp::encode(&2u8));
}
