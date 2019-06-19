// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type ChildrenMerkleTable = [MerkleHash; CHILDREN_COUNT];
pub type MaybeMerkleTable = Option<ChildrenMerkleTable>;
pub type MaybeMerkleTableRef<'a> = Option<&'a ChildrenMerkleTable>;

pub fn compute_merkle_for_rlp(rlp_stream: &RlpStream) -> MerkleHash {
    keccak(rlp_stream.as_raw())
}

pub fn compute_node_merkle(
    children_merkles: MaybeMerkleTableRef, maybe_value: Option<&[u8]>,
) -> MerkleHash {
    let mut rlp_stream = RlpStream::new();
    rlp_stream.begin_unbounded_list();
    match children_merkles {
        Some(merkles) => {
            rlp_stream.append_list(merkles);
        }
        _ => {}
    }
    match maybe_value {
        Some(value) => {
            rlp_stream.append(&value);
        }
        _ => {}
    }
    rlp_stream.complete_unbounded_list();

    compute_merkle_for_rlp(&rlp_stream)
}

fn compute_path_merkle(
    compressed_path: CompressedPathRef, node_merkle: &MerkleHash,
) -> MerkleHash {
    if compressed_path.path_slice().len() != 0 {
        let mut rlp_stream = RlpStream::new_list(3);
        compressed_path.rlp_append_parts(&mut rlp_stream);
        rlp_stream.append(node_merkle);

        compute_merkle_for_rlp(&rlp_stream)
    } else {
        *node_merkle
    }
}

pub fn compute_merkle(
    compressed_path: CompressedPathRef, children_merkles: MaybeMerkleTableRef,
    maybe_value: Option<&[u8]>,
) -> MerkleHash
{
    let node_merkle = compute_node_merkle(children_merkles, maybe_value);
    let path_merkle = compute_path_merkle(compressed_path, &node_merkle);

    path_merkle
}

use super::*;
use crate::hash::keccak;
use primitives::MerkleHash;
use rlp::*;
