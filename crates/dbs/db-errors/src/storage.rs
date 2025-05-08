// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use primitives::account::AccountError;
use std::{io, num};
use thiserror::Error;
type DeltaMptId = u16;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Account(#[from] AccountError),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    IntegerConversionError(#[from] std::num::TryFromIntError),

    #[error(transparent)]
    ParseIntError(#[from] num::ParseIntError),

    #[error(transparent)]
    RlpDecodeError(#[from] rlp::DecoderError),

    #[error(transparent)]
    SqliteError(#[from] sqlite::Error),

    #[error(transparent)]
    StrfmtFmtError(#[from] strfmt::FmtError),

    #[error("Out of capacity")]
    OutOfCapacity,

    #[error("Out of memory.")]
    OutOfMem,

    #[error("Slab: invalid position accessed")]
    SlabKeyError,

    #[error("Key not found.")]
    MPTKeyNotFound,

    #[error("Invalid key length {length}. length must be within [1, {length_limit}].")]
    MPTInvalidKeyLength { length: usize, length_limit: usize },

    #[error("Invalid value length {length}. Length must be less than {length_limit}")]
    MPTInvalidValueLength { length: usize, length_limit: usize },

    #[error("Too many nodes.")]
    MPTTooManyNodes,

    #[error("State commit called before computing Merkle hash.")]
    StateCommitWithoutMerkleHash,

    #[error("Not allowed to operate on an readonly empty db.")]
    DbNotExist,

    // TODO(yz): add error details.
    #[error("Unexpected result from db query.")]
    DbValueError,

    #[error("Db is unclean.")]
    DbIsUnclean,

    #[error("Failed to create new snapshot by COW. Use XFS on linux or APFS on Mac.")]
    SnapshotCowCreation,

    #[error("Failed to copy a snapshot.")]
    SnapshotCopyFailure,

    #[error("Snapshot file not found.")]
    SnapshotNotFound,

    #[error("Attempting to create or modify a Snapshot which already exists.")]
    SnapshotAlreadyExists,

    #[error("Trie node not found when loading Snapshot MPT.")]
    SnapshotMPTTrieNodeNotFound,

    #[error("Too many Delta MPTs created ({}).", DeltaMptId::max_value())]
    TooManyDeltaMPT,

    #[error("Attempting to create a Delta MPT which already exists.")]
    DeltaMPTAlreadyExists,

    #[error("Can't find requested Delta MPT in registry.")]
    DeltaMPTEntryNotFound,

    #[error(
        "Error(s) happened in Delta MPT destroy, error_1: {e1:?}, error_2: {e2:?}"
    )]
    DeltaMPTDestroyErrors {
        e1: Option<Box<Error>>,
        e2: Option<Box<Error>>,
    },

    #[error(
        "The operation \"{0}\" isn't possible on freshly synced snapshot."
    )]
    UnsupportedByFreshlySyncedSnapshot(&'static str),

    #[error("Trie proof is invalid.")]
    InvalidTrieProof,

    #[error("Snapshot sync proof is invalid")]
    InvalidSnapshotSyncProof,

    #[error("Failed to create unit test data dir.")]
    FailedToCreateUnitTestDataDir,

    #[error("Thread panicked with message {0:?}.")]
    ThreadPanicked(String),

    #[error("Error from std::sync::mpsc.")]
    MpscError,

    #[error(
        "tokio::sync::Semaphore::try_acquire(): the semaphore is unavailable."
    )]
    SemaphoreTryAcquireError,

    #[error(
        "tokio::sync::Semaphore::acquire(): the semaphore is unavailable."
    )]
    SemaphoreAcquireError,

    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<String> for Error {
    fn from(e: String) -> Self { Error::Msg(e) }
}
impl From<&str> for Error {
    fn from(e: &str) -> Self { Error::Msg(e.into()) }
}
