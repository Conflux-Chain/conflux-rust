// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Address, H256, U256};
use rlp::*;

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

#[derive(Default, Clone, Debug)]
pub struct StorageValue {
    pub value: U256,
    pub owner: Option<Address>,
}

impl Decodable for StorageValue {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.is_list() {
            if rlp.item_count()? != 2 {
                return Err(DecoderError::RlpIncorrectListLen);
            }
            Ok(StorageValue {
                value: rlp.val_at(0)?,
                owner: Some(rlp.val_at(1)?),
            })
        } else {
            Ok(StorageValue {
                value: rlp.as_val()?,
                owner: None,
            })
        }
    }
}

impl Encodable for StorageValue {
    fn rlp_append(&self, s: &mut RlpStream) {
        match &self.owner {
            Some(owner) => {
                s.begin_list(2).append(&self.value).append(owner);
            }
            None => {
                s.append_internal(&self.value);
            }
        }
    }
}
