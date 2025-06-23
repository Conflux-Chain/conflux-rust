// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::U64;
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, str::FromStr};

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum BlockNumber {
    /// Number
    Num(U64),
    /// Earliest block (true genesis)
    Earliest,
    /// The latest committed
    LatestCommitted,
    /// The latest voted
    LatestVoted,
}

impl Default for BlockNumber {
    fn default() -> Self { BlockNumber::LatestCommitted }
}

impl FromStr for BlockNumber {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest_committed" => Ok(BlockNumber::LatestCommitted),
            "latest_voted" => Ok(BlockNumber::LatestVoted),
            "earliest" => Ok(BlockNumber::Earliest),
            _ if s.starts_with("0x") => u64::from_str_radix(&s[2..], 16)
                .map(U64::from)
                .map(BlockNumber::Num)
                .map_err(|e| format!("Invalid block number: {}", e)),
            _ => Err("Invalid block number: missing 0x prefix".to_string()),
        }
    }
}

impl Into<BlockNumber> for u64 {
    fn into(self) -> BlockNumber { BlockNumber::Num(U64::from(self)) }
}

impl<'a> Deserialize<'a> for BlockNumber {
    fn deserialize<D>(deserializer: D) -> Result<BlockNumber, D::Error>
    where D: Deserializer<'a> {
        deserializer.deserialize_any(BlockNumberVisitor)
    }
}

impl Serialize for BlockNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            BlockNumber::Num(ref x) => {
                serializer.serialize_str(&format!("0x{:x}", x))
            }
            BlockNumber::Earliest => serializer.serialize_str("earliest"),
            BlockNumber::LatestCommitted => {
                serializer.serialize_str("latest_committed")
            }
            BlockNumber::LatestVoted => {
                serializer.serialize_str("latest_voted")
            }
        }
    }
}

struct BlockNumberVisitor;

impl<'a> Visitor<'a> for BlockNumberVisitor {
    type Value = BlockNumber;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "an block number or 'latest_committed' or 'latest_voted' or 'earliest'")
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
