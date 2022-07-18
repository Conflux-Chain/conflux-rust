// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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

use crate::rpc::{
    error_codes::{internal_error, invalid_params},
    types::eth::{BlockNumber, Log},
};
use cfx_types::{Space, H160, H256};
use cfxcore::SharedConsensusGraph;
use jsonrpc_core::Error as RpcError;
use primitives::{
    filter::{LogFilter as PrimitiveFilter, LogFilterParams},
    EpochNumber,
};
use serde::{
    de::{DeserializeOwned, Error},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::{from_value, Value};
use std::convert::TryInto;

/// Variadic value
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum VariadicValue<T>
where T: DeserializeOwned
{
    /// Single
    Single(T),
    /// List
    Multiple(Vec<T>),
    /// None
    Null,
}

impl<'a, T> Deserialize<'a> for VariadicValue<T>
where T: DeserializeOwned
{
    fn deserialize<D>(deserializer: D) -> Result<VariadicValue<T>, D::Error>
    where D: Deserializer<'a> {
        let v: Value = Deserialize::deserialize(deserializer)?;

        if v.is_null() {
            return Ok(VariadicValue::Null);
        }

        from_value(v.clone())
            .map(VariadicValue::Single)
            .or_else(|_| from_value(v).map(VariadicValue::Multiple))
            .map_err(|err| {
                D::Error::custom(format!(
                    "Invalid variadic value type: {}",
                    err
                ))
            })
    }
}

impl<T> VariadicValue<T>
where T: DeserializeOwned
{
    pub fn to_vec(self) -> Vec<T> {
        match self {
            VariadicValue::Null => vec![],
            VariadicValue::Single(x) => vec![x],
            VariadicValue::Multiple(xs) => xs,
        }
    }

    pub fn to_opt(self) -> Option<Vec<T>> {
        match self {
            VariadicValue::Null => None,
            VariadicValue::Single(x) => Some(vec![x]),
            VariadicValue::Multiple(xs) => Some(xs),
        }
    }
}

/// Filter Address
pub type FilterAddress = VariadicValue<H160>;
/// Topic
pub type Topic = VariadicValue<H256>;

/// Filter
#[derive(Debug, PartialEq, Clone, Deserialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct EthRpcLogFilter {
    /// From Block
    pub from_block: Option<BlockNumber>,
    /// To Block
    pub to_block: Option<BlockNumber>,
    /// Block hash
    pub block_hash: Option<H256>,
    /// Address
    pub address: Option<FilterAddress>,
    /// Topics
    pub topics: Option<Vec<Topic>>,
}

impl EthRpcLogFilter {
    pub fn into_primitive(
        self, consensus: SharedConsensusGraph,
    ) -> Result<PrimitiveFilter, RpcError> {
        let params = LogFilterParams {
            address: self.address.map(|v| v.to_vec()),
            topics: self
                .topics
                .unwrap_or(vec![])
                .into_iter()
                .map(|t| t.to_opt())
                .collect(),
            trusted: false,
            space: Space::Ethereum,
        };

        match (&self.from_block, &self.to_block, &self.block_hash) {
            // block hash filter
            (None, None, Some(block_hash)) => {
                // check if `block_hash` is a valid pivot hash
                let epoch = consensus
                    .get_block_epoch_number(block_hash)
                    .ok_or(invalid_params("blockHash", "Unknown block"))?;

                let hashes = consensus
                    .get_block_hashes_by_epoch(EpochNumber::Number(epoch))
                    .map_err(|_| {
                        invalid_params("blockHash", "Unknown block")
                    })?;

                let pivot_hash = hashes
                    .last()
                    .ok_or(internal_error("Inconsistent state"))?;

                if block_hash != pivot_hash {
                    bail!(invalid_params("blockHash", "Unknown block"));
                }

                // filter based on a single epoch
                Ok(PrimitiveFilter::EpochLogFilter {
                    from_epoch: EpochNumber::Number(epoch),
                    to_epoch: EpochNumber::Number(epoch),
                    params,
                })
            }

            // block number range filter
            // note: blocks in EVM space RPCs correspond to epochs
            (_, _, None) => {
                let from_epoch = match self.from_block {
                    // FIXME(thegaram): this is probably not consistent with eth
                    None => EpochNumber::LatestState,
                    Some(bn) => bn.try_into()?,
                };

                let to_epoch = match self.to_block {
                    None => EpochNumber::LatestState,
                    Some(bn) => bn.try_into()?,
                };

                Ok(PrimitiveFilter::EpochLogFilter {
                    from_epoch,
                    to_epoch,
                    params,
                })
            }

            // any other case is considered an error
            _ => {
                bail!(RpcError::invalid_params(
                    format!("Filter must provide one of the following: (1) a block number range through `fromBlock` and `toBlock`, (2) a set of block hashes through `blockHash`")
                ));
            }
        }
    }
}

// impl Filter {
//     pub fn try_into(self) -> Result<EthFilter, RpcError> {
//         if self.block_hash.is_some() && (self.from_block.is_some() ||
// self.to_block.is_some()) {             return Err(invalid_params(
//                 "blockHash",
//                 "blockHash is mutually exclusive with fromBlock/toBlock",
//             ));
//         }
//
//         let num_to_id = |num| match num {
//             BlockNumber::Hash { hash, .. } => BlockId::Hash(hash),
//             BlockNumber::Num(n) => BlockId::Number(n),
//             BlockNumber::Earliest => BlockId::Earliest,
//             BlockNumber::Latest | BlockNumber::Pending => BlockId::Latest,
//         };
//
//         let (from_block, to_block) = match self.block_hash {
//             Some(hash) => (BlockId::Hash(hash), BlockId::Hash(hash)),
//             None => (
//                 self.from_block.map_or_else(|| BlockId::Latest, &num_to_id),
//                 self.to_block.map_or_else(|| BlockId::Latest, &num_to_id),
//             ),
//         };
//
//         Ok(EthFilter {
//             from_block,
//             to_block,
//             address: self.address.and_then(|address| match address {
//                 VariadicValue::Null => None,
//                 VariadicValue::Single(a) => Some(vec![a]),
//                 VariadicValue::Multiple(a) => Some(a),
//             }),
//             topics: {
//                 let mut iter = self
//                     .topics
//                     .map_or_else(Vec::new, |topics| {
//                         topics
//                             .into_iter()
//                             .take(4)
//                             .map(|topic| match topic {
//                                 VariadicValue::Null => None,
//                                 VariadicValue::Single(t) => Some(vec![t]),
//                                 VariadicValue::Multiple(t) => Some(t),
//                             })
//                             .collect()
//                     })
//                     .into_iter();
//
//                 vec![
//                     iter.next().unwrap_or(None),
//                     iter.next().unwrap_or(None),
//                     iter.next().unwrap_or(None),
//                     iter.next().unwrap_or(None),
//                 ]
//             },
//             limit: self.limit,
//         })
//     }
// }

/// Results of the filter_changes RPC.
#[derive(Debug, PartialEq)]
pub enum FilterChanges {
    /// New logs.
    Logs(Vec<Log>),
    /// New hashes (block or transactions)
    Hashes(Vec<H256>),
    /// Empty result,
    Empty,
}

impl Serialize for FilterChanges {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            FilterChanges::Logs(ref logs) => logs.serialize(s),
            FilterChanges::Hashes(ref hashes) => hashes.serialize(s),
            FilterChanges::Empty => (&[] as &[Value]).serialize(s),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::{Filter, Topic, VariadicValue};
//     use ethereum_types::H256;
//     use serde_json;
//     use std::str::FromStr;
//     use types::{filter::Filter as EthFilter, ids::BlockId};
//     use v1::types::BlockNumber;
//
//     #[test]
//     fn topic_deserialization() {
//         let s =
// r#"["0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
// null, ["0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
// "0x0000000000000000000000000aff3454fce5edbc8cca8697c15331677e6ebccc"]]"#;
//         let deserialized: Vec<Topic> = serde_json::from_str(s).unwrap();
//         assert_eq!(
//             deserialized,
//             vec![
//                 VariadicValue::Single(
//                     H256::from_str(
//
// "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
//                     )
//                     .unwrap()
//                     .into()
//                 ),
//                 VariadicValue::Null,
//                 VariadicValue::Multiple(vec![
//                     H256::from_str(
//
// "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
//                     )
//                     .unwrap()
//                     .into(),
//                     H256::from_str(
//
// "0000000000000000000000000aff3454fce5edbc8cca8697c15331677e6ebccc"
//                     )
//                     .unwrap()
//                     .into(),
//                 ])
//             ]
//         );
//     }
//
//     #[test]
//     fn filter_deserialization() {
//         let s = r#"{"fromBlock":"earliest","toBlock":"latest"}"#;
//         let deserialized: Filter = serde_json::from_str(s).unwrap();
//         assert_eq!(
//             deserialized,
//             Filter {
//                 from_block: Some(BlockNumber::Earliest),
//                 to_block: Some(BlockNumber::Latest),
//                 block_hash: None,
//                 address: None,
//                 topics: None,
//                 limit: None,
//             }
//         );
//     }
//
//     #[test]
//     fn filter_conversion() {
//         let filter = Filter {
//             from_block: Some(BlockNumber::Earliest),
//             to_block: Some(BlockNumber::Latest),
//             block_hash: None,
//             address: Some(VariadicValue::Multiple(vec![])),
//             topics: Some(vec![
//                 VariadicValue::Null,
//                 VariadicValue::Single(
//                     H256::from_str(
//
// "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
//                     )
//                     .unwrap(),
//                 ),
//                 VariadicValue::Null,
//             ]),
//             limit: None,
//         };
//
//         let eth_filter: EthFilter = filter.try_into().unwrap();
//         assert_eq!(
//             eth_filter,
//             EthFilter {
//                 from_block: BlockId::Earliest,
//                 to_block: BlockId::Latest,
//                 address: Some(vec![]),
//                 topics: vec![
//                     None,
//                     Some(vec![H256::from_str(
//
// "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
//                     )
//                     .unwrap()]),
//                     None,
//                     None,
//                 ],
//                 limit: None,
//             }
//         );
//     }
// }
