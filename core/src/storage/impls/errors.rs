// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{io, num};

error_chain! {
    links {
    }

    foreign_links {
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

        // TODO(yz): encode key into error message.
        MPTInvalidKey {
            description("Invalid key."),
            display("Invalid key."),
        }

        // TODO(yz): encode value into error message.
        MPTInvalidValue {
            description("Invalid value."),
            display("Invalid value."),
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

        SnapshotMPTTrieNodeNotFound {
            description("Trie node not found when loading Snapshot MPT."),
            display("Trie node not found when loading Snapshot MPT."),
        }

        DeltaMPTAlreadyExists {
            description("Attempting to create a Delta MPT which already exists."),
            display("Attempting to create a Delta MPT which already exists."),
        }

        DeltaMPTEntryNotFound {
            description("Can't find requested Delta MPT in registry."),
            display("Can't find requested Delta MPT in registry."),
        }

        InvalidTrieProof {
            description("Trie proof is invalid."),
            display("Trie proof is invalid."),
        }

        InvalidSnapshotSyncProof {
            description("Snapshot sync proof is invalid"),
            display("Snapshot sync proof is invalid"),
        }
    }
}
