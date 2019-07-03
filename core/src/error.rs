// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Address, H256, U256};
use primitives::{filter::FilterError, transaction::TransactionError};
use std::{error, fmt, time::SystemTime};
use unexpected::{Mismatch, OutOfBounds};

#[derive(Debug, PartialEq, Clone, Copy, Eq)]
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
    /// Timestamp header field is invalid.
    InvalidTimestamp(OutOfBounds<SystemTime>),
    /// Timestamp header field is too far in future.
    TemporarilyInvalid(OutOfBounds<SystemTime>),
    /// Too many transactions from a particular address.
    TooManyTransactions(Address),
    /// Parent given is unknown.
    UnknownParent(H256),
    /// Duplicate parent or referee hashes exist.
    DuplicateParentOrRefereeHashes(H256),
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
            TooManyTransactions(ref address) => {
                format!("Too many transactions from: {}", address)
            }
            DuplicateParentOrRefereeHashes(ref hash) => {
                format!("Duplicate parent or referee hashes: {}", hash)
            }
        };

        f.write_fmt(format_args!("Block error ({})", msg))
    }
}

impl error::Error for BlockError {
    fn description(&self) -> &str { "Block error" }
}

error_chain! {
    types {
        Error, ErrorKind, ErrorResultExt, CoreResult;
    }

    foreign_links {
        Block(BlockError) #[doc = "Error concerning block processing."];
        Transaction(TransactionError) #[doc = "Error concerning transaction processing."];
        Filter(FilterError) #[doc = "Error concerning log filtering."];
    }

    errors {
        #[doc = "PoW hash is invalid or out of date."]
        PowHashInvalid {
            description("PoW hash is invalid or out of date.")
            display("PoW hash is invalid or out of date.")
        }
    }
}
