// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::hash::KECCAK_EMPTY;
use cfx_types::H256;

pub type MerkleHash = H256;

/// The Merkle Hash for an empty MPT (either as a subtree or as a whole tree).
pub const MERKLE_NULL_NODE: MerkleHash = KECCAK_EMPTY;
