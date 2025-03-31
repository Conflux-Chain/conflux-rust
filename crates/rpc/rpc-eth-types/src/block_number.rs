// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2022 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::Error;
use cfx_types::H256;
use primitives::EpochNumber;
use serde::{
    de::{Error as SerdeError, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{convert::TryFrom, fmt};

/// Represents rpc api block number param.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum BlockNumber {
    /// Hash
    Hash {
        /// block hash
        hash: H256,
        /// only return blocks part of the canon chain
        // note: we only keep this for compatibility
        require_canonical: bool,
    },
    /// Number
    Num(u64),
    /// Latest block
    Latest,
    /// Earliest block (genesis)
    Earliest,
    /// Pending block (being mined)
    Pending,
    /// Compatibility tag support for ethereum "safe" tag. Will reflect to
    /// "latest_confirmed"
    Safe,
    /// Finalized block
    Finalized,
}

impl Default for BlockNumber {
    fn default() -> Self { BlockNumber::Latest }
}

impl<'a> Deserialize<'a> for BlockNumber {
    fn deserialize<D>(deserializer: D) -> Result<BlockNumber, D::Error>
    where D: Deserializer<'a> {
        deserializer.deserialize_any(BlockNumberVisitor)
    }
}

impl BlockNumber {
    /// Convert block number to min block target.
    pub fn to_min_block_num(&self) -> Option<u64> {
        match *self {
            BlockNumber::Num(ref x) => Some(*x),
            _ => None,
        }
    }
}

impl Serialize for BlockNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            BlockNumber::Hash {
                hash,
                require_canonical,
            } => serializer.serialize_str(&format!(
                "{{ 'hash': '{}', 'requireCanonical': '{}'  }}",
                hash, require_canonical
            )),
            BlockNumber::Num(ref x) => {
                serializer.serialize_str(&format!("0x{:x}", x))
            }
            BlockNumber::Latest => serializer.serialize_str("latest"),
            BlockNumber::Earliest => serializer.serialize_str("earliest"),
            BlockNumber::Pending => serializer.serialize_str("pending"),
            BlockNumber::Safe => serializer.serialize_str("safe"),
            BlockNumber::Finalized => serializer.serialize_str("finalized"),
        }
    }
}

struct BlockNumberVisitor;

impl<'a> Visitor<'a> for BlockNumberVisitor {
    type Value = BlockNumber;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a block number or 'latest', 'earliest' or 'pending'"
        )
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where V: MapAccess<'a> {
        let (mut require_canonical, mut block_number, mut block_hash) =
            (false, None::<u64>, None::<H256>);

        loop {
            let key_str: Option<String> = visitor.next_key()?;

            match key_str {
                Some(key) => match key.as_str() {
                    "blockNumber" => {
                        let value: String = visitor.next_value()?;
                        if value.starts_with("0x") {
                            let number = u64::from_str_radix(&value[2..], 16)
                                .map_err(|e| {
                                SerdeError::custom(format!(
                                    "Invalid block number: {}",
                                    e
                                ))
                            })?;

                            block_number = Some(number);
                            break;
                        } else {
                            return Err(SerdeError::custom(
                                "Invalid block number: missing 0x prefix"
                                    .to_string(),
                            ));
                        }
                    }
                    "blockHash" => {
                        block_hash = Some(visitor.next_value()?);
                    }
                    "requireCanonical" => {
                        require_canonical = visitor.next_value()?;
                    }
                    key => {
                        return Err(SerdeError::custom(format!(
                            "Unknown key: {}",
                            key
                        )))
                    }
                },
                None => break,
            };
        }

        if let Some(number) = block_number {
            return Ok(BlockNumber::Num(number));
        }

        if let Some(hash) = block_hash {
            return Ok(BlockNumber::Hash {
                hash,
                require_canonical,
            });
        }

        return Err(SerdeError::custom("Invalid input"));
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: SerdeError {
        match value {
            "latest" => Ok(BlockNumber::Latest),
            "earliest" => Ok(BlockNumber::Earliest),
            "pending" => Ok(BlockNumber::Pending),
            "safe" => Ok(BlockNumber::Safe),
            "finalized" => Ok(BlockNumber::Finalized),
            _ if value.starts_with("0x") => {
                u64::from_str_radix(&value[2..], 16)
                    .map(BlockNumber::Num)
                    .map_err(|e| {
                        SerdeError::custom(format!(
                            "Invalid block number: {}",
                            e
                        ))
                    })
            }
            _ => Err(SerdeError::custom(
                "Invalid block number: missing 0x prefix".to_string(),
            )),
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where E: SerdeError {
        self.visit_str(value.as_ref())
    }
}

impl TryFrom<BlockNumber> for EpochNumber {
    type Error = Error;

    fn try_from(x: BlockNumber) -> Result<EpochNumber, Error> {
        match x {
            BlockNumber::Num(num) => Ok(EpochNumber::Number(num)),
            BlockNumber::Latest => Ok(EpochNumber::LatestState),
            BlockNumber::Earliest => Ok(EpochNumber::Earliest),
            BlockNumber::Pending => Ok(EpochNumber::LatestState),
            BlockNumber::Safe => Ok(EpochNumber::LatestConfirmed),
            BlockNumber::Finalized => Ok(EpochNumber::LatestFinalized),
            BlockNumber::Hash { .. } => Err(Error::InvalidParams(
                "block_num".into(),
                "Expected block number, found block hash".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn block_number_deserialization() {
        let s = r#"[
			"0xa",
			"latest",
			"earliest",
			"pending",
            "safe",
            "finalized",
			{"blockNumber": "0xa"},
			{"blockHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"},
			{"blockHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", "requireCanonical": true}
		]"#;
        let deserialized: Vec<BlockNumber> = serde_json::from_str(s).unwrap();

        assert_eq!(
            deserialized,
            vec![
                BlockNumber::Num(10),
                BlockNumber::Latest,
                BlockNumber::Earliest,
                BlockNumber::Pending,
                BlockNumber::Safe,
                BlockNumber::Finalized,
                BlockNumber::Num(10),
                BlockNumber::Hash {
                    hash: H256::from_str(
                        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                    )
                    .unwrap(),
                    require_canonical: false
                },
                BlockNumber::Hash {
                    hash: H256::from_str(
                        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                    )
                    .unwrap(),
                    require_canonical: true
                }
            ]
        )
    }

    #[test]
    fn should_not_deserialize() {
        let s = r#"[{}, "10"]"#;
        assert!(serde_json::from_str::<Vec<BlockNumber>>(s).is_err());
    }
}
