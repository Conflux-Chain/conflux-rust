// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use primitives::StorageRoot as PrimitiveStorageRoot;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageRoot {
    delta: H256,
    intermediate: H256,
    snapshot: H256,
}

impl StorageRoot {
    pub fn from_primitive(p: PrimitiveStorageRoot) -> StorageRoot {
        StorageRoot {
            delta: p.delta.into(),
            intermediate: p.intermediate.into(),
            snapshot: p.snapshot.into(),
        }
    }
}
