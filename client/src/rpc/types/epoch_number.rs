// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use primitives::{
    BlockHashOrEpochNumber as PrimitiveBlockHashOrEpochNumber,
    EpochNumber as PrimitiveEpochNumber,
};
use serde::{
    de::{Error, MapAccess, Visitor},
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
    ///
    LatestFinalized,
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
            EpochNumber::LatestFinalized => {
                serializer.serialize_str("latest_finalized")
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
            EpochNumber::LatestFinalized => {
                PrimitiveEpochNumber::LatestFinalized
            }
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
            "latest_finalized" => Ok(EpochNumber::LatestFinalized),
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
            "an epoch number or 'latest_mined', 'latest_state', 'latest_checkpoint', 'latest_finalized', 'latest_confirmed' or 'earliest'"
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
    BlockHashWithOption {
        hash: H256,
        /// Refer to BlockHashOrEpochNumberVisitor
        /// for implementation detail
        require_pivot: Option<bool>,
    },
    EpochNumber(EpochNumber),
}

impl BlockHashOrEpochNumber {
    pub fn into_primitive(self) -> PrimitiveBlockHashOrEpochNumber {
        match self {
            BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot,
            } => PrimitiveBlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot,
            },
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
            BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot,
            } => {
                // If require_pivot is None,
                // serialize to the format of "hash:0x..."
                if let Some(require_pivot) = require_pivot {
                    serializer.serialize_str(&format!(
                        "{{ 'hash': '{}', 'requirePivot': '{}'  }}",
                        hash, require_pivot
                    ))
                } else {
                    serializer.serialize_str(&format!("hash:{:#x}", hash))
                }
            }
        }
    }
}

struct BlockHashOrEpochNumberVisitor;

// In order to keep compatibility with legacy "hash:0x..." format parameter
// the `require_pivot` field is designed to be Option<bool>
// if input is "hash:0x..." then `require_pivot` will be None
// else if input is a object { blockHash: 0x... }
// the `require_pivot` will be Some and default to true
impl<'a> Visitor<'a> for BlockHashOrEpochNumberVisitor {
    type Value = BlockHashOrEpochNumber;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "an epoch number or 'latest_mined', 'latest_state', 'latest_checkpoint', 'latest_finalized', \
             'latest_confirmed', or 'earliest', or 'hash:<BLOCK_HASH>'"
        )
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where V: MapAccess<'a> {
        // require_pivot defaults to true if input is a map
        let (mut require_pivot, mut epoch_number, mut block_hash) =
            (true, None::<u64>, None::<H256>);

        // following the implementaion in rpc/types/eth/block_number.rs
        loop {
            let key_str: Option<String> = visitor.next_key()?;

            match key_str {
                Some(key) => match key.as_str() {
                    "epochNumber" => {
                        let value: String = visitor.next_value()?;
                        if value.starts_with("0x") {
                            let number = u64::from_str_radix(&value[2..], 16)
                                .map_err(|e| {
                                Error::custom(format!(
                                    "Invalid epoch number: {}",
                                    e
                                ))
                            })?;

                            epoch_number = Some(number.into());
                            break;
                        } else {
                            return Err(Error::custom(
                                "Invalid block number: missing 0x prefix"
                                    .to_string(),
                            ));
                        }
                    }
                    "blockHash" => {
                        block_hash = Some(visitor.next_value()?);
                    }
                    "requirePivot" => {
                        require_pivot = visitor.next_value()?;
                    }
                    key => {
                        return Err(Error::custom(format!(
                            "Unknown key: {}",
                            key
                        )))
                    }
                },
                None => break,
            };
        }

        if let Some(number) = epoch_number {
            return Ok(BlockHashOrEpochNumber::EpochNumber(EpochNumber::Num(
                number.into(),
            )));
        }

        if let Some(hash) = block_hash {
            return Ok(BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot: Some(require_pivot),
            });
        }

        return Err(Error::custom("Invalid input"));
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: Error {
        if value.starts_with("hash:0x") {
            Ok(BlockHashOrEpochNumber::BlockHashWithOption {
                hash: value[7..].parse().map_err(Error::custom)?,
                require_pivot: None,
            })
        } else {
            value.parse().map_err(Error::custom).map(
                |epoch_number: EpochNumber| {
                    BlockHashOrEpochNumber::EpochNumber(epoch_number)
                },
            )
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where E: Error {
        self.visit_str(value.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn block_hash_or_epoch_number_deserialization() {
        let s = r#"[
			"0xa",
			"latest_state",
			"earliest",
            "latest_mined",
            "latest_checkpoint",
            "latest_confirmed",
            "latest_finalized",
            "hash:0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            {"epochNumber": "0xa"},
			{"blockHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"},
			{"blockHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", "requirePivot": false}
		]"#;
        let deserialized: Vec<BlockHashOrEpochNumber> =
            serde_json::from_str(s).unwrap();

        assert_eq!(
            deserialized,
            vec![
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::Num((10).into())),
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestState),
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::Earliest),
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestMined),
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestCheckpoint),
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestConfirmed),
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestFinalized),
                BlockHashOrEpochNumber::BlockHashWithOption {
                    hash: H256::from_str(
                        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                    )
                    .unwrap(),
                    // the "hash:0x..." will return an object with 
                    // require_pivot = None
                    require_pivot: None
                },
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::Num((10).into())),
                BlockHashOrEpochNumber::BlockHashWithOption {
                    hash: H256::from_str(
                        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                    )
                    .unwrap(),
                    require_pivot: Some(true)
                },
                BlockHashOrEpochNumber::BlockHashWithOption {
                    hash: H256::from_str(
                        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                    )
                    .unwrap(),
                    require_pivot: Some(false)
                }
            ]
        )
    }

    #[test]
    fn should_not_deserialize() {
        let s = r#"[{}, "10"]"#;
        assert!(serde_json::from_str::<Vec<BlockHashOrEpochNumber>>(s).is_err());
    }
}
