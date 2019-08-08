// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{io, num};

error_chain! {
    links {
    }

    foreign_links {
        Io(io::Error);
        ParseIntError(num::ParseIntError);
        RlpDecodeError(::rlp::DecoderError);
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
    }
}
