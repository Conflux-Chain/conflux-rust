// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// The MSB is used to indicate if a node is in mem or on disk,
/// the rest 31 bits specifies the index of the node in the
/// memory region.
///
/// It's necessary to use MaybeNodeRef in ChildrenTable because it consumes less
/// space than NodeRef.
#[derive(Copy, Clone, Debug, Eq, PartialEq, MallocSizeOfDerive)]
pub struct NodeRefDeltaMptCompact {
    value: u32,
}

impl NodeRefTrait for NodeRefDeltaMptCompact {}

#[derive(Copy, Clone, Debug, Eq, PartialEq, MallocSizeOfDerive)]
pub struct MaybeNodeRefDeltaMptCompact {
    value: u32,
}

impl Default for MaybeNodeRefDeltaMptCompact {
    fn default() -> Self {
        Self { value: Self::NULL }
    }
}

impl NodeRefDeltaMptCompact {
    /// Valid dirty slot ranges from [0..DIRTY_SLOT_LIMIT).
    /// The DIRTY_SLOT_LIMIT is reserved for MaybeNodeRefDeltaMptCompact#NULL.
    pub const DIRTY_SLOT_LIMIT: u32 = 0x7fffffff;
    const PERSISTENT_KEY_BIT: u32 = 0x80000000;

    pub fn new(value: u32) -> Self {
        Self { value }
    }
}

impl MaybeNodeRefDeltaMptCompact {
    pub const NULL: u32 = 0;
    pub const NULL_NODE: MaybeNodeRefDeltaMptCompact =
        MaybeNodeRefDeltaMptCompact { value: Self::NULL };

    pub fn new(value: u32) -> Self {
        Self { value }
    }
}

// Manages access to a TrieNode. Converted from MaybeNodeRef. NodeRef is not
// copy because it controls access to TrieNode.
#[derive(Clone, Eq, PartialOrd, PartialEq, Ord, Debug, MallocSizeOfDerive)]
pub enum NodeRefDeltaMpt {
    Committed { db_key: DeltaMptDbKey },
    Dirty { index: ActualSlabIndex },
}

impl From<NodeRefDeltaMpt> for NodeRefDeltaMptCompact {
    fn from(node: NodeRefDeltaMpt) -> Self {
        match node {
            NodeRefDeltaMpt::Committed { db_key } => Self {
                value: db_key ^ NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT,
            },
            NodeRefDeltaMpt::Dirty { index } => Self {
                value: index ^ NodeRefDeltaMptCompact::DIRTY_SLOT_LIMIT,
            },
        }
    }
}

impl From<NodeRefDeltaMptCompact> for NodeRefDeltaMpt {
    fn from(x: NodeRefDeltaMptCompact) -> Self {
        if NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT & x.value == 0 {
            NodeRefDeltaMpt::Dirty {
                index: (NodeRefDeltaMptCompact::DIRTY_SLOT_LIMIT ^ x.value),
            }
        } else {
            NodeRefDeltaMpt::Committed {
                db_key: (NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT ^ x.value),
            }
        }
    }
}

impl From<MaybeNodeRefDeltaMptCompact> for Option<NodeRefDeltaMpt> {
    fn from(x: MaybeNodeRefDeltaMptCompact) -> Self {
        if x.value == MaybeNodeRefDeltaMptCompact::NULL {
            None
        } else {
            Some(NodeRefDeltaMptCompact::new(x.value).into())
        }
    }
}

impl From<Option<NodeRefDeltaMpt>> for MaybeNodeRefDeltaMptCompact {
    fn from(maybe_node: Option<NodeRefDeltaMpt>) -> Self {
        match maybe_node {
            None => MaybeNodeRefDeltaMptCompact::NULL_NODE,
            Some(node) => MaybeNodeRefDeltaMptCompact::new(
                NodeRefDeltaMptCompact::from(node).value,
            ),
        }
    }
}

impl Decodable for NodeRefDeltaMptCompact {
    fn decode(rlp: &Rlp) -> ::std::result::Result<Self, DecoderError> {
        Ok(NodeRefDeltaMptCompact {
            value: rlp.as_val()?,
        })
    }
}

impl Encodable for NodeRefDeltaMptCompact {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_internal(&self.value);
    }
}

use super::{
    super::merkle_patricia_trie::NodeRefTrait,
    node_memory_manager::ActualSlabIndex, node_ref_map::DeltaMptDbKey,
};
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
use rlp::*;
