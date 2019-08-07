// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{compressed_path::*, trie_node::TrieNodeTrait};
use std::cmp::min;

/// Key length should be multiple of 8.
// TODO(yz): align key @8B with mask.
pub type KeyPart<'a> = &'a [u8];

pub enum WalkStop<'key, ChildIdType> {
    // path matching fails at some point. Want the new path_steps,
    // path_end_mask, ..., etc Basically, a new node should be created to
    // replace the current node from parent children table;
    // modify this node or create a new node to insert as children of new
    // node, (update path) then
    // the child that should be followed is nil at the new node.
    // if put single version, this node changes, this node replaced, parent
    // update child and merkle. Before merkle update, this node must be saved
    // in mem or into disk db (not that expensive). if get / delete (not
    // found)
    PathDiverted {
        /// Key may terminate on the path.
        key_child_index: Option<u8>,
        key_remaining: KeyPart<'key>,
        matched_path: CompressedPathRaw,
        unmatched_child_index: u8,
        unmatched_path_remaining: CompressedPathRaw,
    },

    // If exactly at this node.
    // if put, update this node
    // if delete, may cause deletion / path compression (delete this node,
    // parent update child, update path of original child node)
    Arrived,

    Descent {
        key_remaining: KeyPart<'key>,
        child_index: u8,
        child_node: ChildIdType,
    },

    // To descent, however child doesn't exists:
    // to modify this node or create a new node to replace this node (update
    // child) Then create a new node for remaining key_part (we don't care
    // about begin_mask). if put single version, this node changes, parent
    // update merkle. if get / delete (not found)
    ChildNotFound {
        key_remaining: KeyPart<'key>,
        child_index: u8,
    },
}

impl<'key, ChildIdType> WalkStop<'key, ChildIdType> {
    pub fn path_diverted_uninitialized() -> Self {
        WalkStop::PathDiverted {
            key_child_index: None,
            key_remaining: Default::default(),
            matched_path: Default::default(),
            unmatched_child_index: 0,
            unmatched_path_remaining: Default::default(),
        }
    }
}

pub mod access_mode {
    pub trait AccessMode {
        fn is_read_only() -> bool;
    }

    pub struct Read {}
    pub struct Write {}

    impl AccessMode for Read {
        fn is_read_only() -> bool { return true; }
    }

    impl AccessMode for Write {
        fn is_read_only() -> bool { return false; }
    }
}

pub(super) trait TrieNodeWalkTrait<'node>: TrieNodeTrait {
    type ChildIdType: 'node;

    fn get_child(&'node self, child_index: u8) -> Option<Self::ChildIdType>;

    fn walk<'key, AM: access_mode::AccessMode>(
        &'node self, key: KeyPart<'key>,
    ) -> WalkStop<'key, Self::ChildIdType> {
        walk::<AM, _>(key, &self.compressed_path_ref(), self)
    }
}

/// Traverse.
// TODO(yz): write test.
///
/// When a trie node start with the second nibble, the trie node has a
/// compressed path of step 1. The nibble in the compressed path is
/// the same as its child index.
///
/// The start of key is always aligned with compressed path of
/// current node, e.g. if compressed path starts at the second-half, so
/// should be key.
pub(super) fn walk<
    'key,
    'node,
    AM: access_mode::AccessMode,
    Node: TrieNodeWalkTrait<'node>,
>(
    key: KeyPart<'key>, path: &dyn CompressedPathTrait, node: &'node Node,
) -> WalkStop<'key, Node::ChildIdType> {
    let path_slice = path.path_slice();
    let path_end_mask = path.end_mask();

    // Compare bytes till the last full byte. The first byte is always
    // included because even if it's the second-half, it must be
    // already matched before entering this TrieNode.
    let memcmp_len = min(
        path_slice.len() - ((path_end_mask != 0) as usize),
        key.len(),
    );

    for i in 0..memcmp_len {
        if path_slice[i] != key[i] {
            if AM::is_read_only() {
                return WalkStop::path_diverted_uninitialized();
            } else {
                let matched_path: CompressedPathRaw;
                let key_child_index: u8;
                let key_remaining: &[u8];
                let unmatched_child_index: u8;
                let unmatched_path_remaining: &[u8];

                if CompressedPathRaw::first_nibble(path_slice[i] ^ key[i]) == 0
                {
                    // "First half" matched
                    matched_path = CompressedPathRaw::new_and_apply_mask(
                        &path_slice[0..i + 1],
                        CompressedPathRaw::first_nibble(!0),
                    );

                    key_child_index = CompressedPathRaw::second_nibble(key[i]);
                    key_remaining = &key[i + 1..];
                    unmatched_child_index =
                        CompressedPathRaw::second_nibble(path_slice[i]);
                    unmatched_path_remaining = &path_slice[i + 1..];
                } else {
                    matched_path = CompressedPathRaw::new(&path_slice[0..i], 0);
                    key_child_index = CompressedPathRaw::first_nibble(key[i]);
                    key_remaining = &key[i..];
                    unmatched_child_index =
                        CompressedPathRaw::first_nibble(path_slice[i]);
                    unmatched_path_remaining = &path_slice[i..];
                }
                return WalkStop::PathDiverted {
                    key_child_index: Some(key_child_index),
                    key_remaining: key_remaining.into(),
                    matched_path,
                    unmatched_child_index,
                    unmatched_path_remaining: CompressedPathRaw::new(
                        unmatched_path_remaining,
                        path_end_mask,
                    ),
                };
            }
        }
    }
    // Key is fully consumed, get value attached.
    if key.len() == memcmp_len {
        // Compressed path isn't fully consumed.
        if path_slice.len() > memcmp_len {
            if AM::is_read_only() {
                return WalkStop::path_diverted_uninitialized();
            } else {
                return WalkStop::PathDiverted {
                    // key_remaining is empty, and key_child_index doesn't
                    // make sense, but we need to
                    // mark it.
                    key_remaining: Default::default(),
                    key_child_index: None,
                    matched_path: CompressedPathRaw::new(
                        &path_slice[0..memcmp_len],
                        0,
                    ),
                    unmatched_child_index: CompressedPathRaw::first_nibble(
                        path_slice[memcmp_len],
                    ),
                    unmatched_path_remaining: CompressedPathRaw::new(
                        &path_slice[memcmp_len..],
                        path_end_mask,
                    ),
                };
            }
        } else {
            return WalkStop::Arrived;
        }
    } else {
        // Key is not fully consumed.

        // When path is fully consumed, check if child exists under
        // child_index.
        let child_index;
        let key_remaining;

        if path_slice.len() == memcmp_len {
            // Compressed path is fully consumed. Descend into one child.
            child_index = CompressedPathRaw::first_nibble(key[memcmp_len]);
            key_remaining = &key[memcmp_len..];
        } else {
            // One half byte remaining to match with path. Consume it in the
            // key.
            if CompressedPathRaw::first_nibble(
                path_slice[memcmp_len] ^ key[memcmp_len],
            ) != 0
            {
                // Mismatch.
                if AM::is_read_only() {
                    return WalkStop::path_diverted_uninitialized();
                } else {
                    return WalkStop::PathDiverted {
                        key_child_index: Some(CompressedPathRaw::first_nibble(
                            key[memcmp_len],
                        )),
                        key_remaining: &key[memcmp_len..],
                        matched_path: CompressedPathRaw::new(
                            &path_slice[0..memcmp_len],
                            0,
                        ),
                        unmatched_child_index: CompressedPathRaw::first_nibble(
                            path_slice[memcmp_len],
                        ),
                        unmatched_path_remaining: CompressedPathRaw::new(
                            &path_slice[memcmp_len..],
                            path_end_mask,
                        ),
                    };
                }
            } else {
                child_index = CompressedPathRaw::second_nibble(key[memcmp_len]);
                key_remaining = &key[memcmp_len + 1..];
            }
        }

        match node.get_child(child_index) {
            Option::None => {
                return WalkStop::ChildNotFound {
                    key_remaining,
                    child_index,
                };
            }
            Option::Some(child_node) => {
                return WalkStop::Descent {
                    key_remaining,
                    child_index,
                    child_node,
                };
            }
        }
    }
}
