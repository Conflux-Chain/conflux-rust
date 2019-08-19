// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::storage::{state::StateTrait, Error, TrieProof};
use primitives::StateRoot;
use rlp_derive::{
    RlpDecodable, RlpDecodableWrapper, RlpEncodable, RlpEncodableWrapper,
};

#[derive(
    Clone, Debug, Hash, Eq, PartialEq, RlpEncodableWrapper, RlpDecodableWrapper,
)]
pub struct ChunkKey {
    path: Vec<u8>, // MPT node key
}

#[derive(RlpEncodable, RlpDecodable)]
pub struct ChunkKeyWithProof {
    pub key: ChunkKey,
    proof: TrieProof,
}

impl ChunkKeyWithProof {
    /// Validate the proof in the chunk key
    pub fn validate(&self, _root: &StateRoot) -> bool { unimplemented!() }
}

#[derive(Default, RlpEncodable, RlpDecodable)]
pub struct RangedManifest {
    pub chunks: Vec<ChunkKeyWithProof>,
    pub next_chunk: Option<ChunkKeyWithProof>,
}

impl RangedManifest {
    /// Validate the proof of all chunk keys
    pub fn validate(&self, root: &StateRoot) -> bool {
        if self.chunks.is_empty() {
            return false;
        }

        for chunk in &self.chunks {
            if !chunk.validate(root) {
                return false;
            }
        }

        if let Some(chunk) = &self.next_chunk {
            if !chunk.validate(root) {
                return false;
            }
        }

        true
    }

    pub fn merge(&mut self, other: RangedManifest) {
        self.chunks.extend(other.chunks);
        self.next_chunk = other.next_chunk;
    }

    /// Validate the integrity of all chunk keys, there should not be any chunk
    /// key missed.
    pub fn validate_integrity(&self, _root: &StateRoot) -> bool {
        unimplemented!()
    }
}

#[derive(Default, RlpEncodableWrapper, RlpDecodableWrapper)]
pub struct Chunk {
    raw: Vec<u8>,
}

impl Chunk {
    /// Validate the chunk with given key and state root
    pub fn validate(&self, _key: &ChunkKey, _root: &StateRoot) -> bool {
        unimplemented!()
    }

    pub fn restore(self, _state: &mut StateTrait) -> Result<(), Error> {
        unimplemented!()
    }
}
