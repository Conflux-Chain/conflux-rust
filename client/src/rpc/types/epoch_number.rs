// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use primitives::EpochNumber as PrimitiveEpochNumber;
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;

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
            EpochNumber::Num(num) => PrimitiveEpochNumber::Number(num.into()),
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
            "a epoch number or 'latest', 'earliest' or 'pending'"
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: Error {
        match value {
            "latest_mined" => Ok(EpochNumber::LatestMined),
            "latest_state" => Ok(EpochNumber::LatestState),
            "earliest" => Ok(EpochNumber::Earliest),
            _ if value.starts_with("0x") => {
                u64::from_str_radix(&value[2..], 16)
                    .map(EpochNumber::Num)
                    .map_err(|e| {
                        Error::custom(format!("Invalid epoch number: {}", e))
                    })
            }
            _ => Err(Error::custom(format!(
                "Invalid epoch number: missing 0x prefix"
            ))),
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where E: Error {
        self.visit_str(value.as_ref())
    }
}
