use crate::key_value::MERKLE_NULL_NODE;
use amt_db::{
    serde::{MyFromBytes, MyToBytes},
    AmtRoot,
};
use cfx_primitives::MerkleHash;
use cfx_types::H256;
use keccak_hash::keccak;

use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
// #[serde(rename_all = "camelCase")]
pub struct StateRoot {
    pub amt_root: AmtRoot,
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
            amt_root: AmtRoot::default(),
            static_root: MERKLE_NULL_NODE,
        }
    }
}

impl Encodable for StateRoot {
    fn rlp_append(&self, s: &mut RlpStream) {
        let serialized_amt_root = self.amt_root.to_bytes_consensus();
        s.begin_list(2)
            .append(&serialized_amt_root)
            .append(&self.static_root);
    }
}

impl Decodable for StateRoot {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let serialized_amt_root: Vec<u8> = rlp.val_at(0).unwrap();
        let static_root = rlp.val_at(1).unwrap();
        let amt_root = AmtRoot::from_bytes_consensus(&serialized_amt_root)
            .map_err(|_| DecoderError::Custom("Curve serialize error"))?;
        Ok(StateRoot {
            amt_root,
            static_root,
        })
    }
}

#[test]
fn test_rlp_serde() {
    let root = StateRoot {
        amt_root: AmtRoot::default(),
        static_root: MERKLE_NULL_NODE,
    };
    let ser_root: Vec<u8> = root.rlp_bytes();
    let deser_root: StateRoot = rlp::decode(&ser_root).unwrap();
    assert_eq!(root, deser_root);
}

impl Serialize for StateRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        todo!()
    }
}

impl<'de> Deserialize<'de> for StateRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        todo!()
    }
}
