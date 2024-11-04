// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use primitives::account::AccountError;
use std::{io, num};
use thiserror::Error;

type DeltaMptId = u16;

error_chain! {
    links {
    }

    foreign_links {
        Account(AccountError);
        Io(io::Error);
        IntegerConversionError(std::num::TryFromIntError);
        ParseIntError(num::ParseIntError);
        RlpDecodeError(rlp::DecoderError);
        SqliteError(sqlite::Error);
        StrfmtFmtError(strfmt::FmtError);
    }

    errors {
        OutOfCapacity {
            description("Out of capacity"),
            display("Out of capacity"),
        }

        OutOfMem {
            description("Out of memory."),
            display("Out of memory."),
        }

        SlabKeyError {
            description("Slab: invalid position accessed"),
            display("Slab: invalid position accessed"),
        }

        MPTKeyNotFound {
            description("Key not found."),
            display("Key not found."),
        }

        MPTInvalidKeyLength(length: usize, length_limit: usize){
            description("Invalid key length."),
            display(
                "Invalid key length {}. length must be within [1, {}].",
                length, length_limit),
        }

        MPTInvalidValueLength(length: usize, length_limit: usize) {
            description("Invalid value length."),
            display(
                "Invalid value length {}. Length must be less than {}",
                length, length_limit),
        }

        MPTTooManyNodes {
            description("Too many nodes."),
            display("Too many nodes."),
        }

        StateCommitWithoutMerkleHash {
            description("State commit called before computing Merkle hash."),
            display("State commit called before computing Merkle hash."),
        }

        DbNotExist {
            description("Not allowed to operate on an readonly empty db."),
            display("Not allowed to operate on an readonly empty db."),
        }

        // TODO(yz): add error details.
        DbValueError {
            description("Unexpected result from db query."),
            display("Unexpected result from db query."),
        }

        DbIsUnclean {
            description("Db is unclean."),
            display("Db is unclean."),
        }

        SnapshotCowCreation {
            description("Failed to create new snapshot by COW."),
            display("Failed to create new snapshot by COW. Use XFS on linux or APFS on Mac."),
        }

        SnapshotCopyFailure {
            description("Failed to directly copy a snapshot."),
            display("Failed to copy a snapshot."),
        }

        SnapshotNotFound {
            description("Snapshot file not found."),
            display("Snapshot file not found."),
        }

        SnapshotAlreadyExists {
            description("Attempting to create or modify a Snapshot which already exists."),
            display("Attempting to create or modify a Snapshot which already exists."),
        }

        SnapshotMPTTrieNodeNotFound {
            description("Trie node not found when loading Snapshot MPT."),
            display("Trie node not found when loading Snapshot MPT."),
        }

        TooManyDeltaMPT {
            description("Too many Delta MPTs created."),
            display("Too many Delta MPTs created ({}).", DeltaMptId::max_value()),
        }

        DeltaMPTAlreadyExists {
            description("Attempting to create a Delta MPT which already exists."),
            display("Attempting to create a Delta MPT which already exists."),
        }

        DeltaMPTEntryNotFound {
            description("Can't find requested Delta MPT in registry."),
            display("Can't find requested Delta MPT in registry."),
        }

        DeltaMPTDestroyErrors(e1: Option<Box<Error>>, e2: Option<Box<Error>>) {
            description("Error(s) happened in Delta MPT destroy"),
            display(
                "Error(s) happened in Delta MPT destroy, error_1: {:?}, error_2: {:?}",
                e1.as_ref().map(|x| format!("{}", &**x)),
                e2.as_ref().map(|x| format!("{}", &**x)),
            ),
        }

        UnsupportedByFreshlySyncedSnapshot(op: &'static str) {
            description("The operation isn't possible on freshly synced snapshot."),
            display("The operation \"{}\" isn't possible on freshly synced snapshot.", op),
        }

        InvalidTrieProof {
            description("Trie proof is invalid."),
            display("Trie proof is invalid."),
        }

        InvalidSnapshotSyncProof {
            description("Snapshot sync proof is invalid"),
            display("Snapshot sync proof is invalid"),
        }

        FailedToCreateUnitTestDataDir {
            description("Failed to create unit test data dir."),
            display("Failed to create unit test data dir."),
        }

        ThreadPanicked(msg: String) {
            description("Thread panicked."),
            display("Thread panicked with message {:?}.", msg),
        }

        MpscError {
            description("Error from std::sync::mpsc."),
            display("Error from std::sync::mpsc."),
        }

        SemaphoreTryAcquireError {
            description("tokio::sync::Semaphore::try_acquire(): the semaphore is unavailable."),
            display("tokio::sync::Semaphore::try_acquire(): the semaphore is unavailable."),
        }
    }
}

#[derive(Debug, Error)]
pub enum Errors {
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
    #[error("Too many Delta MPTs created ({}).", DeltaMptId::MAX)]
    TooManyDeltaMPT,
    #[error("Attempting to create a Delta MPT which already exists.")]
    DeltaMPTAlreadyExists,
    #[error("Can't find requested Delta MPT in registry.")]
    DeltaMPTEntryNotFound,
    #[error("Error(s) happened in Delta MPT destroy, error_1: {:?}, error_2: {:?}",.e1.as_ref().map(|x| format!("{}", &**x)), .e2.as_ref().map(|x| format!("{}", &**x)))]
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
}
