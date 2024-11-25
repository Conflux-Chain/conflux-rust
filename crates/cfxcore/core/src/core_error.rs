// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::message::Bytes;
use cfx_types::{Address, SpaceMap, H256, U256};
use primitives::{filter::FilterError, transaction::TransactionError};
use std::{error, fmt, time::SystemTime};
use thiserror::Error;
use unexpected::{Mismatch, OutOfBounds};

#[derive(Debug, PartialEq, Clone, Eq)]
/// Errors concerning block processing.
pub enum BlockError {
    /// Number field of header is invalid.
    InvalidHeight(Mismatch<u64>),
    /// Block has too much gas used.
    TooMuchGasUsed(OutOfBounds<U256>),
    /// State root header field is invalid.
    InvalidStateRoot(Mismatch<H256>),
    /// Gas used header field is invalid.
    InvalidGasUsed(Mismatch<U256>),
    /// Transactions root header field is invalid.
    InvalidTransactionsRoot(Mismatch<H256>),
    /// Difficulty is out of range; this can be used as an looser error prior
    /// to getting a definitive value for difficulty. This error needs only
    /// provide bounds of which it is out.
    DifficultyOutOfBounds(OutOfBounds<U256>),
    /// Difficulty header field is invalid; this is a strong error used after
    /// getting a definitive value for difficulty (which is provided).
    InvalidDifficulty(OutOfBounds<U256>),
    /// Proof-of-work aspect of seal, which we assume is a 256-bit value, is
    /// invalid.
    InvalidProofOfWork(OutOfBounds<H256>),
    /// Gas limit header field is invalid.
    InvalidGasLimit(OutOfBounds<U256>),
    /// Total gas limits of transactions in block is out of bound.
    InvalidPackedGasLimit(OutOfBounds<U256>),
    /// Total rlp sizes of transactions in block is out of bound.
    InvalidBlockSize(OutOfBounds<u64>),
    InvalidBasePrice(Mismatch<SpaceMap<U256>>),
    /// Timestamp header field is invalid.
    InvalidTimestamp(OutOfBounds<SystemTime>),
    /// Timestamp header field is too far in future.
    TemporarilyInvalid(OutOfBounds<SystemTime>),
    /// Too many referees in a block
    TooManyReferees(OutOfBounds<usize>),
    /// Too long custom data in header
    TooLongCustomInHeader(OutOfBounds<usize>),
    /// Too many transactions from a particular address.
    TooManyTransactions(Address),
    /// Parent given is unknown.
    UnknownParent(H256),
    /// Duplicate parent or referee hashes exist.
    DuplicateParentOrRefereeHashes(H256),
    /// The value in `custom` does not match the specification.
    InvalidCustom(Vec<Bytes>, Vec<Bytes>),
    /// Should have a PoS reference but it's not set.
    MissingPosReference,
    /// Should not have a PoS reference but it's set.
    UnexpectedPosReference,
    /// Should have a base fee but it's not set.
    MissingBaseFee,
    /// Should not have a base fee but it's set.
    UnexpectedBaseFee,
    /// The PoS reference violates the validity rule (it should extend the PoS
    /// reference of the parent and referees).
    InvalidPosReference,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BlockError::*;

        let msg = match *self {
            InvalidHeight(ref mis) => format!("Invalid block height: {}", mis),
            TooMuchGasUsed(ref oob) => {
                format!("Block has too much gas used. {}", oob)
            }
            InvalidStateRoot(ref mis) => {
                format!("Invalid state root in header: {}", mis)
            }
            InvalidGasUsed(ref mis) => {
                format!("Invalid gas used in header: {}", mis)
            }
            InvalidTransactionsRoot(ref mis) => {
                format!("Invalid transactions root in header: {}", mis)
            }
            DifficultyOutOfBounds(ref oob) => {
                format!("Invalid block difficulty: {}", oob)
            }
            InvalidDifficulty(ref oob) => {
                format!("Invalid block difficulty: {}", oob)
            }
            InvalidProofOfWork(ref oob) => {
                format!("Block has invalid PoW: {}", oob)
            }
            InvalidGasLimit(ref oob) => format!("Invalid gas limit: {}", oob),
            InvalidBasePrice(ref mis) => {
                format!("Invalid base price: {:?}", mis)
            }
            InvalidPackedGasLimit(ref oob) => {
                format!("Invalid packed gas limit: {}", oob)
            }
            InvalidBlockSize(ref oob) => format!("Invalid block size: {}", oob),
            InvalidTimestamp(ref oob) => {
                let oob =
                    oob.map(|st| st.elapsed().unwrap_or_default().as_secs());
                format!("Invalid timestamp in header: {}", oob)
            }
            TemporarilyInvalid(ref oob) => {
                let oob =
                    oob.map(|st| st.elapsed().unwrap_or_default().as_secs());
                format!("Future timestamp in header: {}", oob)
            }
            UnknownParent(ref hash) => format!("Unknown parent: {}", hash),
            TooManyReferees(ref num) => format!("Too many referees: {}", num),
            TooLongCustomInHeader(ref num) => {
                format!("Too long custom data in block header: {}", num)
            }
            TooManyTransactions(ref address) => {
                format!("Too many transactions from: {}", address)
            }
            DuplicateParentOrRefereeHashes(ref hash) => {
                format!("Duplicate parent or referee hashes: {}", hash)
            }
            InvalidCustom(ref header_custom, ref expected_custom_prefix) => {
                format!(
                    "Invalid custom in header: expect prefix {:?}, get {:?}",
                    expected_custom_prefix, header_custom
                )
            }
            MissingPosReference => "Missing PoS reference".into(),
            UnexpectedPosReference => "Should not have PoS reference".into(),
            MissingBaseFee => "Missing base fee".into(),
            UnexpectedBaseFee => "Should not have base fee".into(),
            InvalidPosReference => "The PoS reference is invalid".into(),
        };

        f.write_fmt(format_args!("Block error ({})", msg))
    }
}

impl error::Error for BlockError {
    fn description(&self) -> &str { "Block error" }
}

#[derive(Error, Debug)]
pub enum CoreError {
    #[error(transparent)]
    Block(#[from] BlockError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Filter(#[from] FilterError),
    #[error("PoW hash is invalid or out of date.")]
    PowHashInvalid,
}
