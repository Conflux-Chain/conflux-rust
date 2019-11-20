// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
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
    Num(u64),
    /// Latest mined block.
    LatestMined,
    /// Latest block with state.
    LatestState,
    /// Earliest epoch (genesis)
    Earliest,
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
            /*            EpochNumber::Pending =>
             * serializer.serialize_str("pending"), */
        }
    }
}

impl EpochNumber {
    pub fn into_primitive(self) -> PrimitiveEpochNumber {
        match self {
            EpochNumber::Earliest => PrimitiveEpochNumber::Earliest,
            EpochNumber::LatestMined => PrimitiveEpochNumber::LatestMined,
            EpochNumber::LatestState => PrimitiveEpochNumber::LatestState,
            EpochNumber::Num(num) => PrimitiveEpochNumber::Number(num),
        }
    }
}

impl FromStr for EpochNumber {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest_mined" => Ok(EpochNumber::LatestMined),
            "latest_state" => Ok(EpochNumber::LatestState),
            "earliest" => Ok(EpochNumber::Earliest),
            _ if s.starts_with("0x") => u64::from_str_radix(&s[2..], 16)
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
    fn into(self) -> EpochNumber { EpochNumber::Num(self) }
}

struct EpochNumberVisitor;

impl<'a> Visitor<'a> for EpochNumberVisitor {
    type Value = EpochNumber;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "an epoch number or 'latest_mined', 'latest_state', or 'earliest'"
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
            "an epoch number or 'latest_mined', 'latest_state', or 'earliest', or 'hash:<BLOCK_HASH>'"
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
