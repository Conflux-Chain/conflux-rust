// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Pub-Sub types.

use super::{Filter, Header, Log};
use cfx_types::{H256, U256};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use serde_json::{from_value, Value};

/// Subscription result.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged, rename_all = "camelCase")]
// NOTE: rename_all does not apply to enum member fields
// see: https://github.com/serde-rs/serde/issues/1061
pub enum Result {
    /// New block header.
    Header(Header),

    /// Log
    Log(Log),

    /// Transaction hash
    TransactionHash(H256),

    /// Epoch
    #[serde(rename_all = "camelCase")]
    Epoch {
        epoch_number: U256,
        epoch_hashes_ordered: Vec<H256>,
    },

    /// Chain reorg
    #[serde(rename_all = "camelCase")]
    ChainReorg { revert_to: U256 },
}

/// Subscription kind.
#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    /// New block headers subscription.
    NewHeads,
    /// Logs subscription.
    Logs,
    /// New Pending Transactions subscription.
    NewPendingTransactions,
    /// Node syncing status subscription.
    Syncing,
    /// Epoch
    Epochs,
}

/// Subscription kind.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Params {
    /// No parameters passed.
    None,
    /// Log parameters.
    Logs(Filter),
}

impl Default for Params {
    fn default() -> Self { Params::None }
}

impl<'a> Deserialize<'a> for Params {
    fn deserialize<D>(
        deserializer: D,
    ) -> ::std::result::Result<Params, D::Error>
    where D: Deserializer<'a> {
        let v: Value = Deserialize::deserialize(deserializer)?;

        if v.is_null() {
            return Ok(Params::None);
        }

        from_value(v).map(Params::Logs).map_err(|e| {
            D::Error::custom(format!("Invalid Pub-Sub parameters: {}", e))
        })
    }
}

//#[cfg(test)]
//mod tests {
//    use serde_json;
//    use super::{Result, Kind, Params};
//    use crate::rpc::types::{Header, Filter};
//    use crate::rpc::types::filter::VariadicValue;
//
//    #[test]
//    fn should_deserialize_kind() {
//        assert_eq!(serde_json::from_str::<Kind>(r#""newHeads""#).unwrap(),
// Kind::NewHeads);        assert_eq!(serde_json::from_str::<Kind>(r#""logs""#).
// unwrap(), Kind::Logs);        assert_eq!(serde_json::from_str::<Kind>(r#""
// newPendingTransactions""#).unwrap(), Kind::NewPendingTransactions);
//        assert_eq!(serde_json::from_str::<Kind>(r#""syncing""#).unwrap(),
// Kind::Syncing);    }
//
//    #[test]
//    fn should_deserialize_logs() {
//        let none = serde_json::from_str::<Params>(r#"null"#).unwrap();
//        assert_eq!(none, Params::None);
//
//        let logs1 = serde_json::from_str::<Params>(r#"{}"#).unwrap();
//        let logs2 =
// serde_json::from_str::<Params>(r#"{"limit":10}"#).unwrap();        let logs3
// = serde_json::from_str::<Params>(
// r#"{"topics":["
// 0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"]}"#
//        ).unwrap();
//        assert_eq!(logs1, Params::Logs(Filter {
//            from_block: None,
//            to_block: None,
//            block_hash: None,
//            address: None,
//            topics: None,
//            limit: None,
//        }));
//        assert_eq!(logs2, Params::Logs(Filter {
//            from_block: None,
//            to_block: None,
//            block_hash: None,
//            address: None,
//            topics: None,
//            limit: Some(10),
//        }));
//        assert_eq!(logs3, Params::Logs(Filter {
//            from_block: None,
//            to_block: None,
//            block_hash: None,
//            address: None,
//            topics: Some(vec![
//
// VariadicValue::Single("
// 000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b".parse().
// unwrap()                )]),
//            limit: None,
//        }));
//    }
//
//    #[test]
//    fn should_serialize_header() {
//        let header = Result::Header(RichHeader {
//            extra_info: Default::default(),
//            inner: Header {
//                hash: Some(Default::default()),
//                parent_hash: Default::default(),
//                uncles_hash: Default::default(),
//                author: Default::default(),
//                miner: Default::default(),
//                state_root: Default::default(),
//                transactions_root: Default::default(),
//                receipts_root: Default::default(),
//                number: Some(Default::default()),
//                gas_used: Default::default(),
//                gas_limit: Default::default(),
//                extra_data: Default::default(),
//                logs_bloom: Default::default(),
//                timestamp: Default::default(),
//                difficulty: Default::default(),
//                seal_fields: vec![Default::default(), Default::default()],
//                size: Some(69.into()),
//            },
//        });
//        let expected =
// r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x0",
// "extraData":"0x","gasLimit":"0x0","gasUsed":"0x0","hash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// logsBloom":"
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
// ,"miner":"0x0000000000000000000000000000000000000000","number":"0x0","
// parentHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// receiptsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// sealFields":["0x","0x"],"sha3Uncles":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","size":"
// 0x45","stateRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// timestamp":"0x0","transactionsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000"}"#;
//        assert_eq!(serde_json::to_string(&header).unwrap(), expected);
//    }
//}
