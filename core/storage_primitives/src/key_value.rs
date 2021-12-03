use cfx_types::H256;
use keccak_hash::{keccak, KECCAK_EMPTY};
use rlp::*;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Serialize, Serializer};
use serde_derive::Deserialize;

#[derive(Clone, Debug, PartialEq)]
pub enum MptValue<ValueType> {
    None,
    TombStone,
    Some(ValueType),
}

impl<ValueType: Serialize> Serialize for MptValue<ValueType> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match self {
            MptValue::None => serializer.serialize_none(),
            MptValue::Some(h) => serializer.serialize_some(h),
            MptValue::TombStone => serializer.serialize_str("TOMBSTONE"),
        }
    }
}

impl<ValueType: Default> MptValue<ValueType> {
    pub fn is_some(&self) -> bool {
        match self {
            MptValue::Some(_) => true,
            _ => false,
        }
    }

    pub fn is_tombstone(&self) -> bool {
        match self {
            MptValue::TombStone => true,
            _ => false,
        }
    }

    pub fn into_option(self) -> Option<ValueType> {
        match self {
            MptValue::None => None,
            MptValue::TombStone => Some(ValueType::default()),
            MptValue::Some(x) => Some(x),
        }
    }

    pub fn take(&mut self) -> Self { std::mem::replace(self, MptValue::None) }

    pub fn unwrap(self) -> ValueType {
        match self {
            MptValue::None => panic!("Unwrapping MptValue::None"),
            MptValue::TombStone => ValueType::default(),
            MptValue::Some(x) => x,
        }
    }
}

impl<ValueType> From<Option<ValueType>> for MptValue<ValueType> {
    fn from(opt: Option<ValueType>) -> MptValue<ValueType> {
        match opt {
            None => MptValue::None,
            Some(v) => MptValue::Some(v),
        }
    }
}

impl Encodable for MptValue<H256> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            MptValue::None => {
                s.begin_list(1).append(&0u8);
            }
            MptValue::TombStone => {
                s.begin_list(1).append(&1u8);
            }
            MptValue::Some(h) => {
                s.begin_list(2).append(&2u8).append(h);
            }
        }
    }
}

impl Decodable for MptValue<H256> {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.val_at(0)? {
            0u8 => Ok(MptValue::None),
            1u8 => Ok(MptValue::TombStone),
            2u8 => Ok(MptValue::Some(rlp.val_at(1)?)),
            n => panic!("Unexpected MptValue type in RLP: {}", n),
        }
    }
}

#[derive(Clone, Debug, RlpEncodable, RlpDecodable, Serialize)]
pub struct NodeMerkleTriplet {
    pub delta: MptValue<H256>,
    pub intermediate: MptValue<H256>,
    pub snapshot: Option<H256>,
}

pub type StorageRoot = NodeMerkleTriplet;

type MerkleHash = H256;

/// The Merkle Hash for an empty MPT (either as a subtree or as a whole tree).
pub const MERKLE_NULL_NODE: MerkleHash = KECCAK_EMPTY;

/// The deferred state root consists of 3 parts: snapshot, delta_0, delta.
/// when delta grows over threshold, snapshot and delta_0 is merged into new
/// snapshot, and the delta becomes new delta_0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRoot {
    pub snapshot_root: MerkleHash,
    pub intermediate_delta_root: MerkleHash,
    pub delta_root: MerkleHash,
}

impl Default for StateRoot {
    fn default() -> Self {
        Self {
            snapshot_root: MERKLE_NULL_NODE,
            intermediate_delta_root: MERKLE_NULL_NODE,
            delta_root: MERKLE_NULL_NODE,
        }
    }
}

impl StateRoot {
    pub fn compute_state_root_hash(&self) -> H256 {
        let mut buffer: [u8; 96] = [0; 96];
        buffer[0..32].copy_from_slice(self.snapshot_root.as_bytes());
        buffer[32..64].copy_from_slice(self.intermediate_delta_root.as_bytes());
        buffer[64..96].copy_from_slice(self.delta_root.as_bytes());
        keccak(&buffer[..])
    }

    pub fn genesis(genesis_root: &MerkleHash) -> StateRoot {
        Self {
            snapshot_root: MERKLE_NULL_NODE,
            intermediate_delta_root: MERKLE_NULL_NODE,
            delta_root: genesis_root.clone(),
        }
    }
}

impl Encodable for StateRoot {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.snapshot_root)
            .append(&self.intermediate_delta_root)
            .append(&self.delta_root);
    }
}

impl Decodable for StateRoot {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            snapshot_root: rlp.val_at(0)?,
            intermediate_delta_root: rlp.val_at(1)?,
            delta_root: rlp.val_at(2)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::MptValue;
    use cfx_primitives::{MerkleHash, MERKLE_NULL_NODE};
    use serde_json;

    #[test]
    fn test_mpt_value_rlp() {
        let val = MptValue::None;

        // list of length 1: rlp(0)
        assert_eq!(rlp::encode(&val), vec![0xc0 + 1, 0x80]);
        assert_eq!(val, rlp::decode(&rlp::encode(&val)).unwrap());

        let val = MptValue::TombStone;

        // list of length 1: rlp(1)
        assert_eq!(rlp::encode(&val), vec![0xc0 + 1, 0x01]);
        assert_eq!(val, rlp::decode(&rlp::encode(&val)).unwrap());

        let val = MptValue::Some(MERKLE_NULL_NODE);

        // list of length 34 (type + 33 for serialized hash): rlp(2) + rlp(hash)
        assert_eq!(
            rlp::encode(&val),
            [&[0xc0 + 34, 0x02][..], &rlp::encode(&MERKLE_NULL_NODE)[..]]
                .concat()
        );
        assert_eq!(val, rlp::decode(&rlp::encode(&val)).unwrap());
    }

    #[test]
    fn test_mpt_value_json() {
        let val = MptValue::<MerkleHash>::None;
        let serialized = serde_json::to_string(&val).unwrap();
        assert_eq!(&serialized, "null");

        let val = MptValue::<MerkleHash>::TombStone;
        let serialized = serde_json::to_string(&val).unwrap();
        assert_eq!(&serialized, "\"TOMBSTONE\"");

        let val = MptValue::<MerkleHash>::Some(MERKLE_NULL_NODE);
        let serialized = serde_json::to_string(&val).unwrap();
        assert_eq!(serialized, format!("\"{:?}\"", MERKLE_NULL_NODE));
    }
}
