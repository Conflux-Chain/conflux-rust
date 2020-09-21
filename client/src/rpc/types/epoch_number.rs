// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use primitives::{
    BlockHashOrEpochNumber as PrimitiveBlockHashOrEpochNumber,
    EpochNumber as PrimitiveEpochNumber,
};
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, str::FromStr};

/// Represents rpc api epoch number param.
#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum EpochNumber {
    /// Number
    Num(U64),
    /// Earliest epoch (true genesis)
    Earliest,
    /// The latest checkpoint (cur_era_genesis)
    LatestCheckpoint,
    /// The latest confirmed (with the estimation of the confirmation meter)
    LatestConfirmed,
    /// Latest block with state.
    LatestState,
    /// Latest mined block.
    LatestMined,
}

//impl Default for EpochNumber {
//    fn default() -> Self { EpochNumber::Latest }
//}

impl<'a> Deserialize<'a> for EpochNumber {
    fn deserialize<D>(deserializer: D) -> Result<EpochNumber, D::Error>
    where D: Deserializer<'a> {
        deserializer.deserialize_any(EpochNumberVisitor)
    }
}

impl Serialize for EpochNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            EpochNumber::Num(ref x) => {
                serializer.serialize_str(&format!("0x{:x}", x))
            }
            EpochNumber::LatestMined => {
                serializer.serialize_str("latest_mined")
            }
            EpochNumber::LatestState => {
                serializer.serialize_str("latest_state")
            }
            EpochNumber::Earliest => serializer.serialize_str("earliest"),
            EpochNumber::LatestCheckpoint => {
                serializer.serialize_str("latest_checkpoint")
            }
            EpochNumber::LatestConfirmed => {
                serializer.serialize_str("latest_confirmed")
            }
        }
    }
}

impl EpochNumber {
    pub fn into_primitive(self) -> PrimitiveEpochNumber {
        match self {
            EpochNumber::Earliest => PrimitiveEpochNumber::Earliest,
            EpochNumber::LatestMined => PrimitiveEpochNumber::LatestMined,
            EpochNumber::LatestState => PrimitiveEpochNumber::LatestState,
            EpochNumber::Num(num) => PrimitiveEpochNumber::Number(num.as_u64()),
            EpochNumber::LatestCheckpoint => {
                PrimitiveEpochNumber::LatestCheckpoint
            }
            EpochNumber::LatestConfirmed => {
                PrimitiveEpochNumber::LatestConfirmed
            }
        }
    }
}

impl FromStr for EpochNumber {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest_mined" => Ok(EpochNumber::LatestMined),
            "latest_state" => Ok(EpochNumber::LatestState),
            "latest_confirmed" => Ok(EpochNumber::LatestConfirmed),
            "earliest" => Ok(EpochNumber::Earliest),
            "latest_checkpoint" => Ok(EpochNumber::LatestCheckpoint),
            _ if s.starts_with("0x") => u64::from_str_radix(&s[2..], 16)
                .map(U64::from)
                .map(EpochNumber::Num)
                .map_err(|e| format!("Invalid epoch number: {}", e)),
            _ => Err("Invalid epoch number: missing 0x prefix".to_string()),
        }
    }
}

impl Into<PrimitiveEpochNumber> for EpochNumber {
    fn into(self) -> PrimitiveEpochNumber { self.into_primitive() }
}

impl Into<EpochNumber> for u64 {
    fn into(self) -> EpochNumber { EpochNumber::Num(U64::from(self)) }
}

struct EpochNumberVisitor;

impl<'a> Visitor<'a> for EpochNumberVisitor {
    type Value = EpochNumber;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "an epoch number or 'latest_mined', 'latest_state', 'latest_checkpoint', 'latest_confirmed' or 'earliest'"
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: Error {
        value.parse().map_err(Error::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where E: Error {
        self.visit_str(value.as_ref())
    }
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum BlockHashOrEpochNumber {
    BlockHash(H256),
    EpochNumber(EpochNumber),
}

impl BlockHashOrEpochNumber {
    pub fn into_primitive(self) -> PrimitiveBlockHashOrEpochNumber {
        match self {
            BlockHashOrEpochNumber::BlockHash(hash) => {
                PrimitiveBlockHashOrEpochNumber::BlockHash(hash)
            }
            BlockHashOrEpochNumber::EpochNumber(epoch_number) => {
                PrimitiveBlockHashOrEpochNumber::EpochNumber(
                    epoch_number.into(),
                )
            }
        }
    }
}

impl Into<PrimitiveBlockHashOrEpochNumber> for BlockHashOrEpochNumber {
    fn into(self) -> PrimitiveBlockHashOrEpochNumber { self.into_primitive() }
}

impl<'a> Deserialize<'a> for BlockHashOrEpochNumber {
    fn deserialize<D>(
        deserializer: D,
    ) -> Result<BlockHashOrEpochNumber, D::Error>
    where D: Deserializer<'a> {
        deserializer.deserialize_any(BlockHashOrEpochNumberVisitor)
    }
}

impl Serialize for BlockHashOrEpochNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match self {
            BlockHashOrEpochNumber::EpochNumber(epoch_number) => {
                epoch_number.serialize(serializer)
            }
            BlockHashOrEpochNumber::BlockHash(block_hash) => {
                serializer.serialize_str(&format!("hash:{:#x}", block_hash))
            }
        }
    }
}

struct BlockHashOrEpochNumberVisitor;

impl<'a> Visitor<'a> for BlockHashOrEpochNumberVisitor {
    type Value = BlockHashOrEpochNumber;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "an epoch number or 'latest_mined', 'latest_state', 'latest_checkpoint',\
             'latest_confirmed', or 'earliest', or 'hash:<BLOCK_HASH>'"
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: Error {
        if value.starts_with("hash:0x") {
            Ok(BlockHashOrEpochNumber::BlockHash(
                value[7..].parse().map_err(Error::custom)?,
            ))
        } else {
            value.parse().map_err(Error::custom).map(|epoch_number| {
                BlockHashOrEpochNumber::EpochNumber(epoch_number)
            })
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where E: Error {
        self.visit_str(value.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::types::{BlockHashOrEpochNumber, EpochNumber};
    use cfx_types::{H256, U64};
    use primitives::{
        BlockHashOrEpochNumber as PrimitiveBlockHashOrEpochNumber,
        EpochNumber as PrimitiveEpochNumber,
    };
    use std::str::FromStr;

    #[test]
    fn test_epoch_number_serialize() {
        let e1 = EpochNumber::Num(U64::one());
        let e2 = EpochNumber::LatestMined;
        let e3 = EpochNumber::LatestCheckpoint;
        let e4 = EpochNumber::LatestConfirmed;
        let e5 = EpochNumber::LatestState;
        let e6 = EpochNumber::Earliest;
        assert_eq!(serde_json::to_string(&e1).unwrap(), r#""0x1""#);
        assert_eq!(serde_json::to_string(&e2).unwrap(), r#""latest_mined""#);
        assert_eq!(
            serde_json::to_string(&e3).unwrap(),
            r#""latest_checkpoint""#
        );
        assert_eq!(
            serde_json::to_string(&e4).unwrap(),
            r#""latest_confirmed""#
        );
        assert_eq!(serde_json::to_string(&e5).unwrap(), r#""latest_state""#);
        assert_eq!(serde_json::to_string(&e6).unwrap(), r#""earliest""#);
    }
    #[test]
    fn test_epoch_number_deserialize() {
        let s1 = r#""0x1""#;
        let s2 = r#""latest_mined""#;
        let s3 = r#""latest_checkpoint""#;
        let s4 = r#""latest_confirmed""#;
        let s5 = r#""latest_state""#;
        let s6 = r#""earliest""#;
        let des1: EpochNumber = serde_json::from_str(s1).unwrap();
        let des2: EpochNumber = serde_json::from_str(s2).unwrap();
        let des3: EpochNumber = serde_json::from_str(s3).unwrap();
        let des4: EpochNumber = serde_json::from_str(s4).unwrap();
        let des5: EpochNumber = serde_json::from_str(s5).unwrap();
        let des6: EpochNumber = serde_json::from_str(s6).unwrap();
        assert_eq!(des1, EpochNumber::Num(U64::one()));
        assert_eq!(des2, EpochNumber::LatestMined);
        assert_eq!(des3, EpochNumber::LatestCheckpoint);
        assert_eq!(des4, EpochNumber::LatestConfirmed);
        assert_eq!(des5, EpochNumber::LatestState);
        assert_eq!(des6, EpochNumber::Earliest);
    }
    #[test]
    fn test_epoch_number_into_primitive() {
        let earliest = EpochNumber::into_primitive(EpochNumber::Earliest);
        let num = EpochNumber::into_primitive(EpochNumber::Num(U64::one()));
        let latest_mined =
            EpochNumber::into_primitive(EpochNumber::LatestMined);
        let latest_checkpoint =
            EpochNumber::into_primitive(EpochNumber::LatestCheckpoint);
        let latest_confirm =
            EpochNumber::into_primitive(EpochNumber::LatestConfirmed);
        let latest_state =
            EpochNumber::into_primitive(EpochNumber::LatestState);
        assert_eq!(earliest, PrimitiveEpochNumber::Earliest);
        assert_eq!(num, PrimitiveEpochNumber::Number(U64::one().as_u64()));
        assert_eq!(latest_mined, PrimitiveEpochNumber::LatestMined);
        assert_eq!(latest_checkpoint, PrimitiveEpochNumber::LatestCheckpoint);
        assert_eq!(latest_confirm, PrimitiveEpochNumber::LatestConfirmed);
        assert_eq!(latest_state, PrimitiveEpochNumber::LatestState);
    }
    #[test]
    fn test_epoch_number_from_str() {
        let earliest = EpochNumber::from_str("earliest");
        let latest_checkpoint = EpochNumber::from_str("latest_checkpoint");
        let latest_confirm = EpochNumber::from_str("latest_confirmed");
        let latest_state = EpochNumber::from_str("latest_state");
        let latest_mined = EpochNumber::from_str("latest_mined");
        let num = EpochNumber::from_str("0x1");
        let error = EpochNumber::from_str("1");
        assert_eq!(earliest.unwrap(), EpochNumber::Earliest);
        assert_eq!(latest_checkpoint.unwrap(), EpochNumber::LatestCheckpoint);
        assert_eq!(latest_confirm.unwrap(), EpochNumber::LatestConfirmed);
        assert_eq!(latest_state.unwrap(), EpochNumber::LatestState);
        assert_eq!(latest_mined.unwrap(), EpochNumber::LatestMined);
        assert_eq!(num.unwrap(), EpochNumber::Num(U64::one()));
        assert_eq!(error.is_err(), true);
    }
    // #[test]
    // fn test_epoch_number_visitor() {
    //     let visitor = EpochNumberVisitor::;
    //
    // }
    #[test]
    fn test_block_hash_or_epoch_number_serialize() {
        let block_hash = BlockHashOrEpochNumber::BlockHash(H256::default());
        let serialize = serde_json::to_string(&block_hash).unwrap();
        assert_eq!(serialize,"\"hash:0x0000000000000000000000000000000000000000000000000000000000000000\"");
        let epoch_number1 =
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::Num(U64::one()));
        let epoch_number2 =
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::Earliest);
        let epoch_number3 =
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestCheckpoint);
        let epoch_number4 =
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestConfirmed);
        let epoch_number5 =
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestState);
        let epoch_number6 =
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestMined);
        let serialize1 = serde_json::to_string(&epoch_number1).unwrap();
        let serialize2 = serde_json::to_string(&epoch_number2).unwrap();
        let serialize3 = serde_json::to_string(&epoch_number3).unwrap();
        let serialize4 = serde_json::to_string(&epoch_number4).unwrap();
        let serialize5 = serde_json::to_string(&epoch_number5).unwrap();
        let serialize6 = serde_json::to_string(&epoch_number6).unwrap();
        assert_eq!(serialize1, "\"0x1\"");
        assert_eq!(serialize2, "\"earliest\"");
        assert_eq!(serialize3, "\"latest_checkpoint\"");
        assert_eq!(serialize4, "\"latest_confirmed\"");
        assert_eq!(serialize5, "\"latest_state\"");
        assert_eq!(serialize6, "\"latest_mined\"");
    }
    #[test]
    fn test_block_hash_or_epoch_number_deserialize() {
        let serialize = "\"hash:0x0000000000000000000000000000000000000000000000000000000000000000\"";
        let deserialize: BlockHashOrEpochNumber =
            serde_json::from_str(serialize).unwrap();
        let block_hash = BlockHashOrEpochNumber::BlockHash(H256::default());
        assert_eq!(deserialize, block_hash);
        let serialize1 = "\"0x1\"";
        let serialize2 = "\"earliest\"";
        let serialize3 = "\"latest_checkpoint\"";
        let serialize4 = "\"latest_confirmed\"";
        let serialize5 = "\"latest_state\"";
        let serialize6 = "\"latest_mined\"";
        let deserialize1: BlockHashOrEpochNumber =
            serde_json::from_str(serialize1).unwrap();
        let deserialize2: BlockHashOrEpochNumber =
            serde_json::from_str(serialize2).unwrap();
        let deserialize3: BlockHashOrEpochNumber =
            serde_json::from_str(serialize3).unwrap();
        let deserialize4: BlockHashOrEpochNumber =
            serde_json::from_str(serialize4).unwrap();
        let deserialize5: BlockHashOrEpochNumber =
            serde_json::from_str(serialize5).unwrap();
        let deserialize6: BlockHashOrEpochNumber =
            serde_json::from_str(serialize6).unwrap();
        assert_eq!(
            deserialize1,
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::Num(U64::one()))
        );
        assert_eq!(
            deserialize2,
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::Earliest)
        );
        assert_eq!(
            deserialize3,
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestCheckpoint)
        );
        assert_eq!(
            deserialize4,
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestConfirmed)
        );
        assert_eq!(
            deserialize5,
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestState)
        );
        assert_eq!(
            deserialize6,
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestMined)
        );
    }
    #[test]
    fn test_block_hash_or_epoch_number_into_primitive() {
        let block_hash = BlockHashOrEpochNumber::into_primitive(
            BlockHashOrEpochNumber::BlockHash(H256::default()),
        );
        let epoch_number = BlockHashOrEpochNumber::into_primitive(
            BlockHashOrEpochNumber::EpochNumber(EpochNumber::Earliest),
        );
        assert_eq!(
            block_hash,
            PrimitiveBlockHashOrEpochNumber::BlockHash(H256::default())
        );
        assert_eq!(
            epoch_number,
            PrimitiveBlockHashOrEpochNumber::EpochNumber(
                PrimitiveEpochNumber::Earliest
            )
        );
    }
}
