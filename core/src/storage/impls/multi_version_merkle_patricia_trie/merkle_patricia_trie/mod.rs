// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod children_table;
pub(self) mod compressed_path;
pub mod cow_node_ref;
pub(self) mod maybe_in_place_byte_array;
pub mod merkle;
pub mod mpt_value;
pub mod node_ref;
pub mod subtrie_visitor;
pub mod trie_node;

#[cfg(test)]
mod tests;

pub use self::{
    children_table::CHILDREN_COUNT,
    compressed_path::{
        CompressedPathRaw, CompressedPathRef, CompressedPathTrait,
    },
    cow_node_ref::CowNodeRef,
    node_ref::{NodeRefDeltaMpt, NodeRefDeltaMptCompact},
    subtrie_visitor::SubTrieVisitor,
    trie_node::TrieNode,
};
pub use primitives::{MerkleHash, MERKLE_NULL_NODE};
