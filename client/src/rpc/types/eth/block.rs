// Copyright 2021 Conflux Foundation. All rights reserved.
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

use crate::rpc::types::{eth::Transaction, Bytes};
use cfx_types::{Bloom as H2048, H160, H256, U256};
use cfxcore::{
    block_data_manager::DataVersionTuple, consensus::ConsensusGraphInner,
};
use primitives::Block as PrimitiveBlock;
use serde::{Serialize, Serializer};

/// Block Transactions
#[derive(Debug)]
pub enum BlockTransactions {
    /// Only hashes
    Hashes(Vec<H256>),
    /// Full transactions
    Full(Vec<Transaction>),
}

impl Serialize for BlockTransactions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            BlockTransactions::Hashes(ref hashes) => {
                hashes.serialize(serializer)
            }
            BlockTransactions::Full(ref ts) => ts.serialize(serializer),
        }
    }
}

/// Block representation
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    /// Hash of the block
    pub hash: Option<H256>,
    /// Hash of the parent
    pub parent_hash: H256,
    /// Hash of the uncles
    #[serde(rename = "sha3Uncles")]
    pub uncles_hash: H256,
    /// Authors address
    pub author: H160,
    /// Alias of `author`
    pub miner: H160,
    /// State root hash
    pub state_root: H256,
    /// Transactions root hash
    pub transactions_root: H256,
    /// Transactions receipts root hash
    pub receipts_root: H256,
    /// Block number
    pub number: Option<U256>,
    /// Gas Used
    pub gas_used: U256,
    /// Gas Limit
    pub gas_limit: U256,
    /// Extra data
    pub extra_data: Bytes,
    /// Logs bloom
    pub logs_bloom: Option<H2048>,
    /// Timestamp
    pub timestamp: U256,
    /// Difficulty
    pub difficulty: U256,
    /// Total difficulty
    pub total_difficulty: Option<U256>,
    /// Seal fields
    pub seal_fields: Vec<Bytes>,
    /// Base fee
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<U256>,
    /// Uncles' hashes
    pub uncles: Vec<H256>,
    /// Transactions
    pub transactions: BlockTransactions,
    /// Size in bytes
    pub size: Option<U256>,
}

/// Block header representation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Hash of the block
    pub hash: Option<H256>,
    /// Hash of the parent
    pub parent_hash: H256,
    /// Hash of the uncles
    #[serde(rename = "sha3Uncles")]
    pub uncles_hash: H256,
    /// Authors address
    pub author: H160,
    /// Alias of `author`
    pub miner: H160,
    /// State root hash
    pub state_root: H256,
    /// Transactions root hash
    pub transactions_root: H256,
    /// Transactions receipts root hash
    pub receipts_root: H256,
    /// Block number
    pub number: Option<U256>,
    /// Gas Used
    pub gas_used: U256,
    /// Gas Limit
    pub gas_limit: U256,
    /// Extra data
    pub extra_data: Bytes,
    /// Logs bloom
    pub logs_bloom: H2048,
    /// Timestamp
    pub timestamp: U256,
    /// Difficulty
    pub difficulty: U256,
    /// Seal fields
    pub seal_fields: Vec<Bytes>,
    /// Base fee
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<U256>,
    /// Size in bytes
    pub size: Option<U256>,
}

impl Block {
    pub fn new(
        b: &PrimitiveBlock, full: bool, consensus_inner: &ConsensusGraphInner,
    ) -> Self {
        // get the block.gas_used
        let tx_len = b.transactions.len();
        let gas_used = if tx_len == 0 {
            Some(U256::from(0))
        } else {
            let maybe_results = consensus_inner
                .block_execution_results_by_hash(
                    &b.hash(),
                    false, /* update_cache */
                );
            match maybe_results {
                Some(DataVersionTuple(_, execution_result)) => {
                    let receipt = execution_result
                        .block_receipts
                        .receipts
                        .get(tx_len - 1)
                        .unwrap();
                    Some(receipt.accumulated_gas_used)
                }
                None => None,
            }
        };

        Block {
            hash: Some(b.block_header.hash()),
            parent_hash: b.block_header.parent_hash().clone(),
            uncles_hash: if let Some(uncle) =
                b.block_header.referee_hashes().first()
            {
                uncle.clone()
            } else {
                H256::zero()
            },
            author: b.block_header.author().clone(),
            miner: b.block_header.author().clone(),
            state_root: b.block_header.deferred_state_root().clone(),
            transactions_root: b.block_header.transactions_root().clone(),
            receipts_root: b.block_header.deferred_receipts_root().clone(),
            number: Some(b.block_header.height().into()), /* We use height to
                                                           * replace block
                                                           * number for ETH
                                                           * interface */
            gas_used: gas_used.unwrap_or(U256::zero()),
            gas_limit: b.block_header.gas_limit().into(),
            extra_data: Default::default(),
            logs_bloom: None, /* TODO: We cannot provide a proper bloom for
                               * ETH interface now */
            timestamp: b.block_header.timestamp().into(),
            difficulty: b.block_header.difficulty().into(),
            total_difficulty: None,
            seal_fields: vec![],
            base_fee_per_gas: None,
            uncles: b.block_header.referee_hashes().clone(),
            transactions: if full {
                BlockTransactions::Full(
                    b.transactions
                        .iter()
                        .map(|t| Transaction::from_signed(t))
                        .collect(),
                )
            } else {
                BlockTransactions::Hashes(b.transaction_hashes())
            },
            size: Some(U256::from(b.size())),
        }
    }
}

// impl Header {
//     pub fn new(h: &EthHeader, eip1559_transition: BlockNumber) -> Self {
//         let eip1559_enabled = h.number() >= eip1559_transition;
//         Header {
//             hash: Some(h.hash()),
// 			size: Some(h.rlp().as_raw().len().into()),
// 			parent_hash: h.parent_hash(),
// 			uncles_hash: h.uncles_hash(),
// 			author: h.author(),
// 			miner: h.author(),
// 			state_root: h.state_root(),
// 			transactions_root: h.transactions_root(),
// 			receipts_root: h.receipts_root(),
// 			number: Some(h.number().into()),
// 			gas_used: h.gas_used(),
// 			gas_limit: h.gas_limit(),
// 			logs_bloom: h.log_bloom(),
// 			timestamp: h.timestamp().into(),
// 			difficulty: h.difficulty(),
// 			extra_data: h.extra_data().into(),
// 			seal_fields: h.view().decode_seal(eip1559_enabled)
// 				.expect("Client/Miner returns only valid headers. We only serialize headers
// from Client/Miner; qed") 				.into_iter().map(Into::into).collect(),
// 			base_fee_per_gas: {
// 				if eip1559_enabled {
// 					Some(h.base_fee())
// 				} else {
// 					None
// 				}
// 			},
// 		}
//     }
// }

// /// Block representation with additional info.
// pub type RichBlock = Rich<Block>;
//
// // /// Header representation with additional info.
// // pub type RichHeader = Rich<Header>;
//
// /// Value representation with additional info
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct Rich<T> {
//     /// Standard value.
//     pub inner: T,
//     /// Engine-specific fields with additional description.
//     /// Should be included directly to serialized block object.
//     // TODO [ToDr] #[serde(skip_serializing)]
//     pub extra_info: BTreeMap<String, String>,
// }
//
// impl<T> Deref for Rich<T> {
//     type Target = T;
//
//     fn deref(&self) -> &Self::Target { &self.inner }
// }
//
// impl<T: Serialize> Serialize for Rich<T> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where S: Serializer {
//         use serde_json::{to_value, Value};
//
//         let serialized = (to_value(&self.inner), to_value(&self.extra_info));
//         if let (Ok(Value::Object(mut value)), Ok(Value::Object(extras))) =
//             serialized
//         {
//             // join two objects
//             value.extend(extras);
//             // and serialize
//             value.serialize(serializer)
//         } else {
//             Err(S::Error::custom(
//                 "Unserializable structures: expected objects",
//             ))
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::{Block, BlockTransactions, Header, RichBlock, RichHeader};
//     use ethereum_types::{Bloom as H2048, H160, H256, H64, U256};
//     use serde_json;
//     use std::collections::BTreeMap;
//     use v1::types::{Bytes, Transaction};
//
//     #[test]
//     fn test_serialize_block_transactions() {
//         let t = BlockTransactions::Full(vec![Transaction::default()]);
//         let serialized = serde_json::to_string(&t).unwrap();
//         assert_eq!(
//             serialized,
//
// r#"[{"hash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"
// 0x0","blockHash":null,"blockNumber":null,"transactionIndex":null,"from":"
// 0x0000000000000000000000000000000000000000","to":null,"value":"0x0","
// gasPrice":"0x0","gas":"0x0","input":"0x","creates":null,"raw":"0x","
// publicKey":null,"chainId":null,"v":"0x0","r":"0x0","s":"0x0","condition":
// null}]"#         );
//
//         let t = BlockTransactions::Hashes(vec![H256::default().into()]);
//         let serialized = serde_json::to_string(&t).unwrap();
//         assert_eq!(
//             serialized,
//
// r#"["0x0000000000000000000000000000000000000000000000000000000000000000"]"#
//         );
//     }
//
//     #[test]
//     fn test_serialize_block() {
//         let block = Block {
//             hash: Some(H256::default()),
//             parent_hash: H256::default(),
//             uncles_hash: H256::default(),
//             author: H160::default(),
//             miner: H160::default(),
//             state_root: H256::default(),
//             transactions_root: H256::default(),
//             receipts_root: H256::default(),
//             number: Some(U256::default()),
//             gas_used: U256::default(),
//             gas_limit: U256::default(),
//             extra_data: Bytes::default(),
//             logs_bloom: Some(H2048::default()),
//             timestamp: U256::default(),
//             difficulty: U256::default(),
//             total_difficulty: Some(U256::default()),
//             seal_fields: vec![Bytes::default(), Bytes::default()],
//             base_fee_per_gas: None,
//             uncles: vec![],
//             transactions: BlockTransactions::Hashes(vec![].into()),
//             size: Some(69.into()),
//         };
//         let serialized_block = serde_json::to_string(&block).unwrap();
//         let rich_block = RichBlock {
//             inner: block,
//             extra_info: map![
//                 "mixHash".into() => format!("{:?}", H256::default()),
//                 "nonce".into() => format!("{:?}", H64::default())
//             ],
//         };
//         let serialized_rich_block =
// serde_json::to_string(&rich_block).unwrap();
//
//         assert_eq!(
//             serialized_block,
//
// r#"{"hash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// parentHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// sha3Uncles":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","author":
// "0x0000000000000000000000000000000000000000","miner":"
// 0x0000000000000000000000000000000000000000","stateRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// transactionsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// receiptsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","number":
// "0x0","gasUsed":"0x0","gasLimit":"0x0","extraData":"0x","logsBloom":"
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
// ,"timestamp":"0x0","difficulty":"0x0","totalDifficulty":"0x0","sealFields":["
// 0x","0x"],"uncles":[],"transactions":[],"size":"0x45"}"#         );
//         assert_eq!(
//             serialized_rich_block,
//
// r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x0",
// "extraData":"0x","gasLimit":"0x0","gasUsed":"0x0","hash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// logsBloom":"
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
// ,"miner":"0x0000000000000000000000000000000000000000","mixHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"
// 0x0000000000000000","number":"0x0","parentHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// receiptsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// sealFields":["0x","0x"],"sha3Uncles":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","size":"
// 0x45","stateRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// timestamp":"0x0","totalDifficulty":"0x0","transactions":[],"transactionsRoot"
// :"0x0000000000000000000000000000000000000000000000000000000000000000","
// uncles":[]}"#         );
//     }
//
//     #[test]
//     fn none_size_null() {
//         let block = Block {
//             hash: Some(H256::default()),
//             parent_hash: H256::default(),
//             uncles_hash: H256::default(),
//             author: H160::default(),
//             miner: H160::default(),
//             state_root: H256::default(),
//             transactions_root: H256::default(),
//             receipts_root: H256::default(),
//             number: Some(U256::default()),
//             gas_used: U256::default(),
//             gas_limit: U256::default(),
//             extra_data: Bytes::default(),
//             logs_bloom: Some(H2048::default()),
//             timestamp: U256::default(),
//             difficulty: U256::default(),
//             total_difficulty: Some(U256::default()),
//             seal_fields: vec![Bytes::default(), Bytes::default()],
//             base_fee_per_gas: None,
//             uncles: vec![],
//             transactions: BlockTransactions::Hashes(vec![].into()),
//             size: None,
//         };
//         let serialized_block = serde_json::to_string(&block).unwrap();
//         let rich_block = RichBlock {
//             inner: block,
//             extra_info: map![
//                 "mixHash".into() => format!("{:?}", H256::default()),
//                 "nonce".into() => format!("{:?}", H64::default())
//             ],
//         };
//         let serialized_rich_block =
// serde_json::to_string(&rich_block).unwrap();
//
//         assert_eq!(
//             serialized_block,
//
// r#"{"hash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// parentHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// sha3Uncles":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","author":
// "0x0000000000000000000000000000000000000000","miner":"
// 0x0000000000000000000000000000000000000000","stateRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// transactionsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// receiptsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","number":
// "0x0","gasUsed":"0x0","gasLimit":"0x0","extraData":"0x","logsBloom":"
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
// ,"timestamp":"0x0","difficulty":"0x0","totalDifficulty":"0x0","sealFields":["
// 0x","0x"],"uncles":[],"transactions":[],"size":null}"#         );
//         assert_eq!(
//             serialized_rich_block,
//
// r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x0",
// "extraData":"0x","gasLimit":"0x0","gasUsed":"0x0","hash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// logsBloom":"
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
// ,"miner":"0x0000000000000000000000000000000000000000","mixHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"
// 0x0000000000000000","number":"0x0","parentHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// receiptsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// sealFields":["0x","0x"],"sha3Uncles":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","size":
// null,"stateRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// timestamp":"0x0","totalDifficulty":"0x0","transactions":[],"transactionsRoot"
// :"0x0000000000000000000000000000000000000000000000000000000000000000","
// uncles":[]}"#         );
//     }
//
//     #[test]
//     fn test_serialize_header() {
//         let header = Header {
//             hash: Some(H256::default()),
//             parent_hash: H256::default(),
//             uncles_hash: H256::default(),
//             author: H160::default(),
//             miner: H160::default(),
//             state_root: H256::default(),
//             transactions_root: H256::default(),
//             receipts_root: H256::default(),
//             number: Some(U256::default()),
//             gas_used: U256::default(),
//             gas_limit: U256::default(),
//             extra_data: Bytes::default(),
//             logs_bloom: H2048::default(),
//             timestamp: U256::default(),
//             difficulty: U256::default(),
//             seal_fields: vec![Bytes::default(), Bytes::default()],
//             base_fee_per_gas: None,
//             size: Some(69.into()),
//         };
//         let serialized_header = serde_json::to_string(&header).unwrap();
//         let rich_header = RichHeader {
//             inner: header,
//             extra_info: map![
//                 "mixHash".into() => format!("{:?}", H256::default()),
//                 "nonce".into() => format!("{:?}", H64::default())
//             ],
//         };
//         let serialized_rich_header =
// serde_json::to_string(&rich_header).unwrap();
//
//         assert_eq!(
//             serialized_header,
//
// r#"{"hash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// parentHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// sha3Uncles":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","author":
// "0x0000000000000000000000000000000000000000","miner":"
// 0x0000000000000000000000000000000000000000","stateRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// transactionsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// receiptsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","number":
// "0x0","gasUsed":"0x0","gasLimit":"0x0","extraData":"0x","logsBloom":"
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
// ,"timestamp":"0x0","difficulty":"0x0","sealFields":["0x","0x"],"size":"0x45"
// }"#         );
//         assert_eq!(
//             serialized_rich_header,
//
// r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x0",
// "extraData":"0x","gasLimit":"0x0","gasUsed":"0x0","hash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// logsBloom":"
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
// ,"miner":"0x0000000000000000000000000000000000000000","mixHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"
// 0x0000000000000000","number":"0x0","parentHash":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// receiptsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// sealFields":["0x","0x"],"sha3Uncles":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","size":"
// 0x45","stateRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000","
// timestamp":"0x0","transactionsRoot":"
// 0x0000000000000000000000000000000000000000000000000000000000000000"}"#
//         );
//     }
// }
