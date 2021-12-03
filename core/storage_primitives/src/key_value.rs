use cfx_types::H256;
use keccak_hash::KECCAK_EMPTY;
use rlp::*;
use serde::{Serialize, Serializer};

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

type MerkleHash = H256;

/// The Merkle Hash for an empty MPT (either as a subtree or as a whole tree).
pub const MERKLE_NULL_NODE: MerkleHash = KECCAK_EMPTY;

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
