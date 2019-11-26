// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[macro_use]
pub(super) mod maybe_in_place_byte_array_macro;

pub mod children_table;
pub(super) mod compressed_path;
pub(super) mod maybe_in_place_byte_array;
pub mod merkle;
pub mod mpt_cursor;
pub mod mpt_merger;
pub mod mpt_value;
pub mod trie_node;
pub mod trie_proof;
pub(super) mod walk;

pub use self::{
    children_table::*,
    compressed_path::{
        CompressedPathRaw, CompressedPathRef, CompressedPathTrait,
    },
    mpt_merger::MptMerger,
    mpt_value::MptValue,
    trie_node::{TrieNodeTrait, VanillaTrieNode},
    trie_proof::TrieProof,
    walk::access_mode,
};

/// Classes implement KVInserter is used to store key-values in MPT iteration.
pub trait KVInserter<Value> {
    fn push(&mut self, v: Value) -> Result<()>;
}

impl<Value> KVInserter<Value> for Vec<Value> {
    fn push(&mut self, v: Value) -> Result<()> { Ok((*self).push(v)) }
}

use super::errors::Result;
