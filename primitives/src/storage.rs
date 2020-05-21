// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::MERKLE_NULL_NODE;
use cfx_types::{Address, H256};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug)]
pub enum StorageLayout {
    Regular(u8), // type: 0, fields: version
}

impl StorageLayout {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            StorageLayout::Regular(version) => vec![0, *version],
        }
    }

    pub fn from_bytes(raw: &[u8]) -> Result<StorageLayout, String> {
        match raw {
            &[0, version] => Ok(StorageLayout::Regular(version)),
            _ => Err(format!("Unknown storage layout: {:?}", raw)),
        }
    }
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct NodeMerkleTriplet {
    pub delta: Option<H256>,
    pub intermediate: Option<H256>,
    pub snapshot: Option<H256>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StorageRoot {
    pub delta: H256,
    pub intermediate: H256,
    pub snapshot: H256,
}

impl StorageRoot {
    pub fn from_node_merkle_triplet(
        t: NodeMerkleTriplet,
    ) -> Option<StorageRoot> {
        match t {
            NodeMerkleTriplet {
                delta: None,
                intermediate: None,
                snapshot: None,
            } => None,
            NodeMerkleTriplet {
                delta,
                intermediate,
                snapshot,
            } => Some(StorageRoot {
                delta: delta.unwrap_or(MERKLE_NULL_NODE),
                intermediate: intermediate.unwrap_or(MERKLE_NULL_NODE),
                snapshot: snapshot.unwrap_or(MERKLE_NULL_NODE),
            }),
        }
    }
}

#[derive(Default, Clone, Debug, RlpDecodable, RlpEncodable)]
pub struct StorageValue {
    pub value: H256,
    pub owner: Address,
}
