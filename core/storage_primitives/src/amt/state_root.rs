use crate::key_value::MERKLE_NULL_NODE;
use cfx_primitives::MerkleHash;
use cfx_types::H256;
use keccak_hash::keccak;
use lvmt_db::{
    serde::{MyFromBytes, MyToBytes},
    LvmtRoot,
};

use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use serde_derive::{
    Deserialize as DeserializeDerive, Serialize as SerializeDerive,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
// #[serde(rename_all = "camelCase")]
pub struct StateRoot {
    pub lvmt_root: LvmtRoot,
    pub static_root: H256,
}
#[derive(
    Clone, Debug, Default, PartialEq, Eq, DeserializeDerive, SerializeDerive,
)]
pub struct StateRootForSerde {
    pub lvmt_root: Vec<u8>,
    pub static_root: H256,
}

impl StateRoot {
    pub fn compute_state_root_hash(&self) -> H256 {
        info!("Compute state root hash");
        keccak(&self.rlp_bytes())
    }

    pub fn genesis(genesis_root: &MerkleHash) -> StateRoot {
        warn!(
            "Make genesis root with dropped parameter {:?}",
            genesis_root
        );
        Self {
            lvmt_root: LvmtRoot::default(),
            static_root: MERKLE_NULL_NODE,
        }
    }
}

impl Encodable for StateRoot {
    fn rlp_append(&self, s: &mut RlpStream) {
        let serialized_lvmt_root = self.lvmt_root.to_bytes_consensus();
        s.begin_list(2)
            .append(&serialized_lvmt_root)
            .append(&self.static_root);
    }
}

impl Decodable for StateRoot {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let serialized_lvmt_root: Vec<u8> = rlp.val_at(0).unwrap();
        let static_root = rlp.val_at(1).unwrap();
        let lvmt_root =
            LvmtRoot::from_bytes_consensus(&serialized_lvmt_root)
                .map_err(|_| DecoderError::Custom("Curve serialize error"))?;
        Ok(StateRoot {
            lvmt_root,
            static_root,
        })
    }
}

#[test]
fn test_rlp_serde() {
    let root = StateRoot {
        lvmt_root: LvmtRoot::default(),
        static_root: MERKLE_NULL_NODE,
    };
    let ser_root: Vec<u8> = root.rlp_bytes();
    let deser_root: StateRoot = rlp::decode(&ser_root).unwrap();
    assert_eq!(root, deser_root);
}

impl Serialize for StateRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let serialized_lvmt_root = self.lvmt_root.to_bytes_local();
        let state_root = StateRootForSerde {
            lvmt_root: serialized_lvmt_root,
            static_root: self.static_root.clone(),
        };
        state_root.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StateRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let state_root = StateRootForSerde::deserialize(deserializer)?;
        Ok(StateRoot {
            lvmt_root: LvmtRoot::from_bytes_local(&state_root.lvmt_root)
                .map_err(|_| D::Error::custom("Curve serialize error"))?,
            static_root: state_root.static_root,
        })
    }
}
