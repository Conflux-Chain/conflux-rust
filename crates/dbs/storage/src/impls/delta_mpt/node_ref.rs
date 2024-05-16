// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type CompactNodeRef = RowNumberUnderlyingType;

/// The MSB is used to indicate if a node is in mem or on disk,
/// the rest 31 bits specifies the index of the node in the
/// memory region.
///
/// It's necessary to use MaybeNodeRef in ChildrenTable because it consumes less
/// space than NodeRef.
#[derive(Copy, Clone, Debug, Eq, PartialEq, MallocSizeOfDerive)]
pub struct NodeRefDeltaMptCompact {
    value: CompactNodeRef,
}

impl NodeRefTrait for NodeRefDeltaMptCompact {}

#[derive(Copy, Clone, Debug, Eq, PartialEq, MallocSizeOfDerive)]
pub struct MaybeNodeRefDeltaMptCompact {
    value: CompactNodeRef,
}

impl Default for MaybeNodeRefDeltaMptCompact {
    fn default() -> Self { Self { value: Self::NULL } }
}

impl NodeRefDeltaMptCompact {
    /// Valid dirty slot ranges from [0..DIRTY_SLOT_LIMIT).
    /// The DIRTY_SLOT_LIMIT is reserved for MaybeNodeRefDeltaMptCompact#NULL.
    pub const DIRTY_SLOT_LIMIT: u32 = 0x7fffffff;
    const LARGE_PERSISTENT_KEY_BIT: CompactNodeRef =
        1 << (CompactNodeRef::BITS - 1);
    /// All the bit operations assume that a persistent key is less than
    /// PERSISTENT_KEY_BIT.
    const PERSISTENT_KEY_BIT: CompactNodeRef = 0x80000000;

    pub fn new(value: CompactNodeRef) -> Self { Self { value } }
}

impl MaybeNodeRefDeltaMptCompact {
    pub const NULL: CompactNodeRef = 0;
    pub const NULL_NODE: MaybeNodeRefDeltaMptCompact =
        MaybeNodeRefDeltaMptCompact { value: Self::NULL };

    pub fn new(value: CompactNodeRef) -> Self { Self { value } }
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
                value: if db_key < NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT {
                    db_key ^ NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT
                } else {
                    if cfg!(feature = "u64_mpt_db_key") {
                        db_key ^ NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT
                            | NodeRefDeltaMptCompact::LARGE_PERSISTENT_KEY_BIT
                    } else {
                        unreachable!("should not run large state with u32 key")
                    }
                },
            },
            NodeRefDeltaMpt::Dirty { index } => Self {
                value: (index ^ NodeRefDeltaMptCompact::DIRTY_SLOT_LIMIT)
                    as CompactNodeRef,
            },
        }
    }
}

impl From<NodeRefDeltaMptCompact> for NodeRefDeltaMpt {
    fn from(x: NodeRefDeltaMptCompact) -> Self {
        if NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT & x.value == 0
            // if `CompactNodeRef` is u32, `PERSISTENT_KEY_BIT` and `LARGE_PERSISTENT_KEY_BIT` are the same.
            && (NodeRefDeltaMptCompact::LARGE_PERSISTENT_KEY_BIT as CompactNodeRef) & x.value == 0
        {
            NodeRefDeltaMpt::Dirty {
                index: (NodeRefDeltaMptCompact::DIRTY_SLOT_LIMIT
                    ^ x.value as u32),
            }
        } else {
            NodeRefDeltaMpt::Committed {
                db_key: (NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT ^ x.value)
                    & !NodeRefDeltaMptCompact::LARGE_PERSISTENT_KEY_BIT,
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
    fn rlp_append(&self, s: &mut RlpStream) { s.append_internal(&self.value); }
}

use super::{
    super::merkle_patricia_trie::NodeRefTrait,
    node_memory_manager::ActualSlabIndex, node_ref_map::DeltaMptDbKey,
};
use crate::impls::delta_mpt::row_number::RowNumberUnderlyingType;
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
use rlp::*;

#[test]
#[cfg(feature = "u64_mpt_db_key")]
fn test_large_key() {
    let db_key = NodeRefDeltaMpt::Committed { db_key: (1 << 32) };
    let compact: NodeRefDeltaMptCompact = db_key.clone().into();
    let a = match db_key {
        NodeRefDeltaMpt::Committed { db_key } => db_key,
        _ => unreachable!(),
    };
    let b = match NodeRefDeltaMpt::from(compact) {
        NodeRefDeltaMpt::Committed { db_key } => db_key,
        _ => unreachable!(),
    };
    assert_eq!(a.to_be_bytes(), b.to_be_bytes());
}
