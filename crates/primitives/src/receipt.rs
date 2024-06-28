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
pub enum TransactionStatus {
    Success = 0,
    Failure = 1,
    Skipped = 2,
}

impl TransactionStatus {
    fn into_u8(&self) -> u8 {
        match self {
            TransactionStatus::Success => 0,
            TransactionStatus::Failure => 1,
            TransactionStatus::Skipped => 2,
        }
    }
}

impl Encodable for TransactionStatus {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_internal(&self.into_u8());
    }
}

impl Decodable for TransactionStatus {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.as_val::<u8>()? {
            0 => Ok(TransactionStatus::Success),
            1 => Ok(TransactionStatus::Failure),
            2 => Ok(TransactionStatus::Skipped),
            _ => Err(DecoderError::Custom("Unrecognized outcome status")),
        }
    }
}

impl Default for TransactionStatus {
    fn default() -> Self { TransactionStatus::Success }
}

impl TransactionStatus {
    pub fn in_space(&self, space: Space) -> u8 {
        match (space, self) {
            // Conflux
            (Space::Native, TransactionStatus::Success) => {
                TRANSACTION_OUTCOME_SUCCESS
            }
            (Space::Native, TransactionStatus::Failure) => {
                TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING
            }
            (Space::Native, TransactionStatus::Skipped) => {
                TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING
            }

            // EVM
            (Space::Ethereum, TransactionStatus::Success) => EVM_SPACE_SUCCESS,
            (Space::Ethereum, TransactionStatus::Failure) => EVM_SPACE_FAIL,
            (Space::Ethereum, TransactionStatus::Skipped) => 0xff,
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SortedStorageChanges {
    pub storage_collateralized: Vec<StorageChange>,
    pub storage_released: Vec<StorageChange>,
}

/// Information describing execution of a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
    pub outcome_status: TransactionStatus,
    /// The designated account to bear the storage fee, if any.
    pub storage_sponsor_paid: bool,
    pub storage_collateralized: Vec<StorageChange>,
    pub storage_released: Vec<StorageChange>,
    pub burnt_gas_fee: Option<U256>,
}

impl Encodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        let length = if self.burnt_gas_fee.is_none() { 9 } else { 10 };
        s.begin_list(length)
            .append(&self.accumulated_gas_used)
            .append(&self.gas_fee)
            .append(&self.gas_sponsor_paid)
            .append(&self.log_bloom)
            .append_list(&self.logs)
            .append(&self.outcome_status)
            .append(&self.storage_sponsor_paid)
            .append_list(&self.storage_collateralized)
            .append_list(&self.storage_released);
        if let Some(burnt_gas_fee) = self.burnt_gas_fee {
            s.append(&burnt_gas_fee);
        }
    }
}

impl Decodable for Receipt {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let item_count = rlp.item_count()?;
        if !matches!(item_count, 9..=10) {
            return Err(DecoderError::RlpIncorrectListLen);
        }
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
            burnt_gas_fee: if item_count == 9 {
                None
            } else {
                Some(rlp.val_at(9)?)
            },
        })
    }
}

impl Receipt {
    pub fn new(
        outcome: TransactionStatus, accumulated_gas_used: U256, gas_fee: U256,
        gas_sponsor_paid: bool, logs: Vec<LogEntry>, log_bloom: Bloom,
        storage_sponsor_paid: bool, storage_collateralized: Vec<StorageChange>,
        storage_released: Vec<StorageChange>, burnt_gas_fee: Option<U256>,
    ) -> Self {
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
            burnt_gas_fee,
        }
    }

    pub fn tx_skipped(&self) -> bool {
        self.outcome_status == TransactionStatus::Skipped
    }

    pub fn tx_success(&self) -> bool {
        self.outcome_status == TransactionStatus::Success
    }

    pub fn accumulated_gas_used(&self) -> U256 { self.accumulated_gas_used }

    pub fn logs(&self) -> &[LogEntry] { &self.logs }
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
    assert_eq!(rlp::encode(&TransactionStatus::Success), rlp::encode(&0u8));
    assert_eq!(rlp::encode(&TransactionStatus::Failure), rlp::encode(&1u8));
    assert_eq!(rlp::encode(&TransactionStatus::Skipped), rlp::encode(&2u8));
}

#[test]
fn test_receipt_rlp_serde() {
    let mut receipt = Receipt {
        accumulated_gas_used: 189000.into(),
        gas_fee: 60054.into(),
        burnt_gas_fee: Some(30027.into()),
        ..Default::default()
    };
    assert_eq!(receipt, Rlp::new(&receipt.rlp_bytes()).as_val().unwrap());

    receipt.burnt_gas_fee = None;
    assert_eq!(receipt, Rlp::new(&receipt.rlp_bytes()).as_val().unwrap());
}
