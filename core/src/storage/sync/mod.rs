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
    /// Check if the chunk key is valid
    pub fn is_valid(&self, _root: &StateRoot) -> bool { unimplemented!() }
}

#[derive(Default, RlpEncodable, RlpDecodable)]
pub struct RangedManifest {
    pub chunks: Vec<ChunkKeyWithProof>,
    pub next_chunk: Option<ChunkKeyWithProof>,
}

impl RangedManifest {
    /// Check if the manifest is valid.
    pub fn is_valid(&self, root: &StateRoot) -> bool {
        if self.chunks.is_empty() {
            return false;
        }

        for chunk in &self.chunks {
            if !chunk.is_valid(root) {
                return false;
            }
        }

        if let Some(chunk) = &self.next_chunk {
            if !chunk.is_valid(root) {
                return false;
            }
        }

        true
    }

    pub fn merge(&mut self, other: RangedManifest) {
        let next_chunk = match self.next_chunk {
            Some(ref chunk) => chunk,
            None => return,
        };

        if other.chunks.is_empty() {
            return;
        }

        if next_chunk.key != other.chunks[0].key {
            return;
        }

        self.chunks.extend(other.chunks);
        self.next_chunk = other.next_chunk;
    }

    /// Check if the integrity of manifest is valid. There should not be any
    /// chunk key missed.
    pub fn is_integrity_valid(&self, _root: &StateRoot) -> bool {
        unimplemented!()
    }
}

#[derive(Default, RlpEncodableWrapper, RlpDecodableWrapper)]
pub struct Chunk {
    raw: Vec<u8>,
}

impl Chunk {
    /// Check if the chunk is valid with given key and state root
    pub fn is_valid(&self, _key: &ChunkKey, _root: &StateRoot) -> bool {
        unimplemented!()
    }

    pub fn insert(self, _state: &mut dyn StateTrait) -> Result<(), Error> {
        unimplemented!()
    }
}
