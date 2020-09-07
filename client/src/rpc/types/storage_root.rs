// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use primitives::StorageRoot as PrimitiveStorageRoot;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
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

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn test_storage_root_serialize() {
        let storage_root = StorageRoot{
            delta: H256([0xff;32]),
            intermediate: H256([0xff;32]),
            snapshot: H256([0xff;32])
        };
        let serialize = serde_json::to_string(&storage_root).unwrap();
        assert_eq!(serialize,"{\"delta\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"intermediate\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"snapshot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"}");
    }
    #[test]
    fn test_storage_root_deserialize() {
        let serialize = "{\"delta\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"intermediate\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"snapshot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"}";
        let deserialize:StorageRoot = serde_json::from_str(serialize).unwrap();
        let storage_root = StorageRoot{
            delta: H256([0xff;32]),
            intermediate: H256([0xff;32]),
            snapshot: H256([0xff;32])
        };
        assert_eq!(deserialize,storage_root);
    }

    #[test]
    fn test_storage_root_from_primitive() {
        let pri_storage_root = PrimitiveStorageRoot{
            delta: H256([0xff;32]),
            intermediate: H256([0xff;32]),
            snapshot: H256([0xff;32])
        };
        let storage_root = StorageRoot::from_primitive(pri_storage_root);
        let storage_root_info =  serde_json::to_string(&storage_root).unwrap();
        assert_eq!(storage_root_info,
        r#"{"delta":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","intermediate":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","snapshot":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}"#);
    }
}