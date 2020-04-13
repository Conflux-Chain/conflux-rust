// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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

pub struct StorageRoot {
    pub delta: H256,
    pub intermediate: H256,
    pub snapshot: H256,
}

#[derive(Default, Clone, Debug, RlpDecodable, RlpEncodable)]
pub struct StorageValue {
    pub value: H256,
    pub owner: Address,
}
