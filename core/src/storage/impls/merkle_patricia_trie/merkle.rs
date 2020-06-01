// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type ChildrenMerkleTable = [MerkleHash; CHILDREN_COUNT];
pub type MaybeMerkleTable = Option<ChildrenMerkleTable>;
pub type MaybeMerkleTableRef<'a> = Option<&'a ChildrenMerkleTable>;

const LEAF_CHILDREN_MERKLE: [MerkleHash; CHILDREN_COUNT] =
    [MERKLE_NULL_NODE; CHILDREN_COUNT];

/// Node merkle for a subtree is defined as keccak(buffer), where buffer
/// contains the relevant trie node representation.
///
/// buffer := 'n' children_merkles maybe_value;
/// children_merkles := path_merkle_of_child_0 ... path_merkle_of_child_15;
/// maybe_value :=   ""     (empty bytes) when maybe_value is None,
///                | 'v' value            when maybe_value is Some(value).
///
/// value can be empty string (to represent TOMBSTONE), therefore we use
/// 'v' to prefix the value.
pub fn compute_node_merkle(
    children_merkles: MaybeMerkleTableRef, maybe_value: Option<&[u8]>,
) -> MerkleHash {
    let mut buffer = Vec::with_capacity(
        1 + std::mem::size_of::<ChildrenMerkleTable>()
            + maybe_value.map_or(0, |v| 1 + v.len()),
    );
    buffer.push('n' as u8);
    let merkles = match children_merkles {
        Some(merkles) => merkles,
        _ => &LEAF_CHILDREN_MERKLE,
    };
    for i in 0..CHILDREN_COUNT {
        buffer.extend_from_slice(merkles[i].as_bytes())
    }

    match maybe_value {
        Some(value) => {
            buffer.push('v' as u8);
            buffer.extend_from_slice(value);
        }
        _ => {}
    }

    keccak(&buffer)
}

/// Path merkle is stored as one of a children merkles in its parent node.
/// It is the merkle of the compressed path combined with a child node.
///
/// path_merkle :=   keccak(buffer) when compressed_path has at least one nibble
///                | node_merkle;
/// buffer := compressed_path_info_byte compressed_path node_merkle;
///
/// compressed_path may exclude half-byte at the beginning or at the end. In
/// these cases, excluded half-byte will be cleared for the merkle computation.
///
/// compressed_path_info_byte := 128 + 64 * (no_first_nibble as bool as int) +
/// compressed_path.path_steps() % 63
///
/// % 63 as we try to avoid power of two which are commonly used in block
/// cipher.
///
/// It's impossible for compressed_path_info_byte to be 'n' used in node merkle
/// calculation.
fn compute_path_merkle(
    compressed_path: CompressedPathRef, without_first_nibble: bool,
    node_merkle: &MerkleHash,
) -> MerkleHash
{
    assert_eq!(
        without_first_nibble,
        CompressedPathRaw::second_nibble(compressed_path.path_mask())
            != CompressedPathRaw::NO_MISSING_NIBBLE,
        "without_first_nibble: {}, path_mask: {}",
        without_first_nibble,
        compressed_path.path_mask(),
    );

    // compressed_path is non-empty.
    if compressed_path.path_steps() > 0 {
        let mut buffer = Vec::with_capacity(
            1 + compressed_path.path_size() as usize
                + std::mem::size_of::<MerkleHash>(),
        );
        // The path_info_byte is defined as:
        // Most significant bit = 1
        // 2nd most significant bit = if the first nibble of the first byte
        // does not belong to the compressed path;
        // least significant 6 bits = number of nibbles in the compressed path %
        // 64.
        let path_info_byte = 128u8
            + 64u8 * (without_first_nibble as u8)
            + (compressed_path.path_steps() as u8) % 63u8;
        buffer.push(path_info_byte);

        buffer.extend_from_slice(compressed_path.path_slice());
        if without_first_nibble {
            // Clear out the first nibble.
            buffer[1] = CompressedPathRaw::second_nibble(buffer[1]);
        }
        buffer.extend_from_slice(node_merkle.as_bytes());

        keccak(buffer)
    } else {
        *node_merkle
    }
}

pub fn compute_merkle(
    compressed_path: CompressedPathRef, path_without_first_nibble: bool,
    children_merkles: MaybeMerkleTableRef, maybe_value: Option<&[u8]>,
) -> MerkleHash
{
    let node_merkle = compute_node_merkle(children_merkles, maybe_value);
    let path_merkle = compute_path_merkle(
        compressed_path,
        path_without_first_nibble,
        &node_merkle,
    );

    path_merkle
}

use super::*;
use crate::hash::keccak;
use primitives::{MerkleHash, MERKLE_NULL_NODE};
