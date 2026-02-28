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
use primitives::{BlockHashOrEpochNumber, EpochNumber};
use serde::{
    de::{Error as SerdeError, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{convert::TryFrom, fmt};

/// Represents rpc api block number param.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum BlockId {
    /// Hash
    Hash {
        /// block hash
        hash: H256,
        /// only return blocks part of the canon chain
        // note: we only keep this for compatibility
        require_canonical: Option<bool>,
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

impl Default for BlockId {
    fn default() -> Self { BlockId::Latest }
}

impl<'a> Deserialize<'a> for BlockId {
    fn deserialize<D>(deserializer: D) -> Result<BlockId, D::Error>
    where D: Deserializer<'a> {
        deserializer.deserialize_any(BlockNumberVisitor)
    }
}

impl BlockId {
    /// Convert block number to min block target.
    pub fn to_min_block_num(&self) -> Option<u64> {
        match *self {
            BlockId::Num(ref x) => Some(*x),
            _ => None,
        }
    }
}

impl Serialize for BlockId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeStruct;

        match *self {
            BlockId::Hash {
                hash,
                require_canonical,
            } => {
                let mut s = serializer.serialize_struct("BlockIdEip1898", 1)?;
                s.serialize_field("blockHash", &hash)?;
                if let Some(require_canonical) = require_canonical {
                    s.serialize_field("requireCanonical", &require_canonical)?;
                }
                s.end()
            }
            BlockId::Num(ref x) => {
                serializer.serialize_str(&format!("0x{:x}", x))
            }
            BlockId::Latest => serializer.serialize_str("latest"),
            BlockId::Earliest => serializer.serialize_str("earliest"),
            BlockId::Pending => serializer.serialize_str("pending"),
            BlockId::Safe => serializer.serialize_str("safe"),
            BlockId::Finalized => serializer.serialize_str("finalized"),
        }
    }
}

struct BlockNumberVisitor;

impl<'a> Visitor<'a> for BlockNumberVisitor {
    type Value = BlockId;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a block number or 'latest', 'earliest' or 'pending'"
        )
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where V: MapAccess<'a> {
        let (mut require_canonical, mut block_number, mut block_hash) =
            (None::<bool>, None::<u64>, None::<H256>);

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
                        require_canonical = Some(visitor.next_value()?);
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
            return Ok(BlockId::Num(number));
        }

        if let Some(hash) = block_hash {
            return Ok(BlockId::Hash {
                hash,
                require_canonical,
            });
        }

        return Err(SerdeError::custom("Invalid input"));
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: SerdeError {
        match value {
            "latest" => Ok(BlockId::Latest),
            "earliest" => Ok(BlockId::Earliest),
            "pending" => Ok(BlockId::Pending),
            "safe" => Ok(BlockId::Safe),
            "finalized" => Ok(BlockId::Finalized),
            _ if value.starts_with("0x") => {
                // Since there is no way to clearly distinguish between a DATA parameter and a QUANTITY parameter. A str is therefore deserialized into a Block Number: <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1898.md>
                // However, since the hex string should be a QUANTITY, we can safely assume that if the len is 66 bytes, it is in fact a hash, ref <https://github.com/ethereum/go-ethereum/blob/ee530c0d5aa70d2c00ab5691a89ab431b73f8165/rpc/types.go#L184-L184>
                if value.len() == 66 {
                    let hash =
                        value[2..].parse().map_err(SerdeError::custom)?;
                    Ok(BlockId::Hash {
                        hash,
                        require_canonical: None,
                    })
                } else {
                    u64::from_str_radix(&value[2..], 16)
                        .map(BlockId::Num)
                        .map_err(|e| {
                            SerdeError::custom(format!(
                                "Invalid block number: {}",
                                e
                            ))
                        })
                }
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

impl TryFrom<BlockId> for EpochNumber {
    type Error = Error;

    fn try_from(x: BlockId) -> Result<EpochNumber, Error> {
        match x {
            BlockId::Num(num) => Ok(EpochNumber::Number(num)),
            BlockId::Latest => Ok(EpochNumber::LatestState),
            BlockId::Earliest => Ok(EpochNumber::Earliest),
            BlockId::Pending => Ok(EpochNumber::LatestMined),
            BlockId::Safe => Ok(EpochNumber::LatestConfirmed),
            BlockId::Finalized => Ok(EpochNumber::LatestFinalized),
            BlockId::Hash { .. } => Err(Error::InvalidParams(
                "block_num".into(),
                "Expected block number, found block hash".into(),
            )),
        }
    }
}

impl From<BlockId> for BlockHashOrEpochNumber {
    fn from(x: BlockId) -> BlockHashOrEpochNumber {
        match x {
            BlockId::Num(num) => {
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::Number(num))
            }
            BlockId::Latest => {
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestState)
            }
            BlockId::Earliest => {
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::Earliest)
            }
            BlockId::Pending => {
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestMined)
            }
            BlockId::Safe => BlockHashOrEpochNumber::EpochNumber(
                EpochNumber::LatestConfirmed,
            ),
            BlockId::Finalized => BlockHashOrEpochNumber::EpochNumber(
                EpochNumber::LatestFinalized,
            ),
            BlockId::Hash {
                hash,
                require_canonical,
            } => BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot: require_canonical,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn block_number_serialization() {
        let hash = H256::from_str(
            "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        )
        .unwrap();

        let block_number = BlockId::Hash {
            hash,
            require_canonical: None,
        };
        let serialized = serde_json::to_string(&block_number).unwrap();
        assert_eq!(
            serialized,
            r#"{"blockHash":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"}"#
        );

        let block_number = BlockId::Hash {
            hash,
            require_canonical: Some(false),
        };
        let serialized = serde_json::to_string(&block_number).unwrap();
        assert_eq!(
            serialized,
            r#"{"blockHash":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","requireCanonical":false}"#
        );

        let block_number = BlockId::Hash {
            hash,
            require_canonical: Some(true),
        };
        let serialized = serde_json::to_string(&block_number).unwrap();
        assert_eq!(
            serialized,
            r#"{"blockHash":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","requireCanonical":true}"#
        );
    }

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
            {"blockHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", "requireCanonical": false},
			{"blockHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", "requireCanonical": true}
		]"#;
        let deserialized: Vec<BlockId> = serde_json::from_str(s).unwrap();

        assert_eq!(
            deserialized,
            vec![
                BlockId::Num(10),
                BlockId::Latest,
                BlockId::Earliest,
                BlockId::Pending,
                BlockId::Safe,
                BlockId::Finalized,
                BlockId::Num(10),
                BlockId::Hash {
                    hash: H256::from_str(
                        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                    )
                    .unwrap(),
                    require_canonical: None,
                },
                BlockId::Hash {
                    hash: H256::from_str(
                        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                    )
                    .unwrap(),
                    require_canonical: Some(false),
                },
                BlockId::Hash {
                    hash: H256::from_str(
                        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                    )
                    .unwrap(),
                    require_canonical: Some(true),
                }
            ]
        )
    }

    #[test]
    fn should_not_deserialize() {
        let s = r#"[{}, "10"]"#;
        assert!(serde_json::from_str::<Vec<BlockId>>(s).is_err());
    }
}
