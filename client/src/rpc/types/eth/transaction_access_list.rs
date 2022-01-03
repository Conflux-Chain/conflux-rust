// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
use cfx_types::{H160, H256};
use serde::Serialize;
use std::vec::Vec;

pub type AccessList = Vec<AccessListItem>;
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    address: H160,
    storage_keys: Vec<H256>,
}

impl AccessListItem {
    pub fn new(address: H160, storage_keys: Vec<H256>) -> Self {
        Self {
            address,
            storage_keys,
        }
    }
}

// impl From<InnerAccessListItem> for AccessListItem {
//     fn from(item: InnerAccessListItem) -> Self {
//         AccessListItem {
//             address: item.0,
//             storage_keys: item.1,
//         }
//     }
// }
//
// impl From<AccessListItem> for InnerAccessListItem {
//     fn from(item: AccessListItem) -> Self {
//         (item.address, item.storage_keys)
//     }
// }
