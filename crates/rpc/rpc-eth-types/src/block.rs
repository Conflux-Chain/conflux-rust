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

use crate::{Bytes, Transaction};
use cfx_rpc_cfx_types::PhantomBlock;
use cfx_types::{
    hexstr_to_h256, Address, Bloom as H2048, Space, H160, H256, H64, U256,
};
use primitives::receipt::EVM_SPACE_SUCCESS;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeMap;

const SHA3_HASH_OF_EMPTY_UNCLE: &str =
    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";

// sha3 hash of empty tx, state, receipt
const SHA3_HASH_OF_EMPTY: &str =
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

/// Block Transactions
#[derive(Debug, Clone)]
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
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    /// Hash of the block
    pub hash: H256,
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
    pub number: U256,
    /// Gas Used
    pub gas_used: U256,
    /// Gas Limit
    pub gas_limit: U256,
    /// Conflux espace gas limit, this is the real gas limit of the block
    /// This is a conflux espace custom field
    pub espace_gas_limit: U256,
    /// Extra data
    pub extra_data: Bytes,
    /// Logs bloom
    pub logs_bloom: H2048,
    /// Timestamp
    pub timestamp: U256,
    /// Difficulty
    pub difficulty: U256,
    /// Total difficulty
    pub total_difficulty: U256,
    /// Base fee
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<U256>,
    /// Uncles' hashes
    pub uncles: Vec<H256>,
    /// Transactions
    pub transactions: BlockTransactions,
    /// Size in bytes
    pub size: U256,
    /// Nonce
    pub nonce: H64,
    /// Mix hash
    pub mix_hash: H256,
}

/// Block header representation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Hash of the block
    pub hash: H256,
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
    pub number: U256,
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
    /// Base fee
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<U256>,
    /// Size in bytes
    pub size: U256,
}

impl Block {
    pub fn from_phantom(pb: &PhantomBlock, full: bool) -> Self {
        let transactions = if full {
            BlockTransactions::Full(
                pb.transactions
                    .iter()
                    .enumerate()
                    .map(|(idx, t)| {
                        let status = pb.receipts[idx]
                            .outcome_status
                            .in_space(Space::Ethereum);

                        let contract_address =
                            match Transaction::deployed_contract_address(&**t) {
                                Some(a) if status == EVM_SPACE_SUCCESS => {
                                    Some(a)
                                }
                                _ => None,
                            };

                        Transaction::from_signed(
                            &**t,
                            (
                                Some(pb.pivot_header.hash()),          // block_hash
                                Some(pb.pivot_header.height().into()), // block_number
                                Some(idx.into()), // transaction_index
                            ),
                            (Some(status.into()), contract_address),
                        )
                    })
                    .collect(),
            )
        } else {
            BlockTransactions::Hashes(
                pb.transactions.iter().map(|t| t.hash()).collect(),
            )
        };

        // If there are no transactions, we use the empty hash for txRoot and
        // receiptRoot. Another way to calculate transactions_root and
        // receipts_root from transactions.
        let (transactions_root, receipts_root) = if pb.transactions.len() > 0 {
            (
                pb.pivot_header.transactions_root().clone(),
                pb.pivot_header.deferred_receipts_root().clone(),
            )
        } else {
            (
                hexstr_to_h256(SHA3_HASH_OF_EMPTY),
                hexstr_to_h256(SHA3_HASH_OF_EMPTY),
            )
        };

        Block {
            hash: pb.pivot_header.hash(),
            parent_hash: pb.pivot_header.parent_hash().clone(),
            uncles_hash: hexstr_to_h256(SHA3_HASH_OF_EMPTY_UNCLE),
            author: pb.pivot_header.author().clone(),
            miner: pb.pivot_header.author().clone(),
            state_root: pb.pivot_header.deferred_state_root().clone(),
            transactions_root,
            receipts_root,
            // We use height to replace block number for ETH interface.
            // Note: this will correspond to the epoch number.
            number: pb.pivot_header.height().into(),
            gas_used: pb
                .receipts
                .last()
                .map(|r| r.accumulated_gas_used)
                .unwrap_or_default(),
            gas_limit: pb.pivot_header.espace_gas_limit(true).into(),
            espace_gas_limit: pb.total_gas_limit,
            extra_data: Default::default(),
            logs_bloom: pb.bloom,
            timestamp: pb.pivot_header.timestamp().into(),
            difficulty: pb.pivot_header.difficulty().into(),
            total_difficulty: 0.into(),
            base_fee_per_gas: pb
                .pivot_header
                .base_price()
                .map(|x| x[Space::Ethereum]),
            uncles: vec![],
            // Note: we allow U256 nonce in Stratum and in the block.
            // However, most mining clients use U64. Here we truncate
            // to U64 to maintain compatibility with eth.
            nonce: pb.pivot_header.nonce().low_u64().to_be_bytes().into(),
            mix_hash: H256::default(),
            transactions,
            size: pb
                .transactions
                .iter()
                .fold(0, |acc, tx| acc + tx.rlp_size())
                .into(),
        }
    }
}

impl Header {
    pub fn from_phantom(pb: &PhantomBlock) -> Self {
        Header {
            hash: pb.pivot_header.hash(),
            parent_hash: pb.pivot_header.parent_hash().clone(),
            uncles_hash: hexstr_to_h256(SHA3_HASH_OF_EMPTY_UNCLE),
            author: pb.pivot_header.author().clone(),
            miner: pb.pivot_header.author().clone(),
            state_root: pb.pivot_header.deferred_state_root().clone(),
            transactions_root: pb.pivot_header.transactions_root().clone(),
            receipts_root: pb.pivot_header.deferred_receipts_root().clone(),
            number: pb.pivot_header.height().into(),
            gas_used: pb
                .receipts
                .last()
                .map(|r| r.accumulated_gas_used)
                .unwrap_or_default(),
            gas_limit: pb.pivot_header.gas_limit().into(),
            extra_data: Default::default(),
            logs_bloom: pb.bloom,
            timestamp: pb.pivot_header.timestamp().into(),
            difficulty: pb.pivot_header.difficulty().into(),
            base_fee_per_gas: None,
            size: pb
                .transactions
                .iter()
                .fold(0, |acc, tx| acc + tx.rlp_size())
                .into(),
        }
    }

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
    // 				.expect("Client/Miner returns only valid headers. We only serialize
    // headers from Client/Miner; qed")
    // .into_iter().map(Into::into).collect(), 			base_fee_per_gas: {
    // 				if eip1559_enabled {
    // 					Some(h.base_fee())
    // 				} else {
    // 					None
    // 				}
    // 			},
    // 		}
    //     }
}

/// BlockOverrides is a set of header fields to override.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockOverrides {
    /// Overrides the block number.
    ///
    /// For `eth_callMany` this will be the block number of the first simulated
    /// block. Each following block increments its block number by 1
    // Note: geth uses `number`, erigon uses `blockNumber`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "blockNumber"
    )]
    pub number: Option<U256>,
    /// Overrides the difficulty of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<U256>,
    /// Overrides the timestamp of the block.
    // Note: geth uses `time`, erigon uses `timestamp`
    #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            alias = "timestamp",
            // with = "alloy_serde::quantity::opt"
        )]
    pub time: Option<u64>,
    /// Overrides the gas limit of the block.
    #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            // with = "alloy_serde::quantity::opt"
        )
    ]
    pub gas_limit: Option<u64>,
    /// Overrides the coinbase address of the block.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "feeRecipient"
    )]
    pub coinbase: Option<Address>,
    /// Overrides the prevrandao of the block.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "prevRandao"
    )]
    pub random: Option<H256>,
    /// Overrides the basefee of the block.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "baseFeePerGas"
    )]
    pub base_fee: Option<U256>,
    /// A dictionary that maps blockNumber to a user-defined hash. It can be
    /// queried from the EVM opcode BLOCKHASH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BTreeMap<u64, H256>>,
}

#[cfg(test)]
mod tests {
    use super::{Block, BlockTransactions};
    use crate::Bytes;
    use cfx_types::{Bloom as H2048, H160, H256, H64, U256};

    #[test]
    fn test_serialize_block() {
        let block = Block {
            hash: H256::default(),
            parent_hash: H256::default(),
            uncles_hash: H256::default(),
            author: H160::default(),
            miner: H160::default(),
            state_root: H256::default(),
            transactions_root: H256::default(),
            receipts_root: H256::default(),
            number: U256::default(),
            gas_used: U256::default(),
            gas_limit: U256::default(),
            espace_gas_limit: U256::default(),
            extra_data: Bytes::default(),
            logs_bloom: H2048::default(),
            timestamp: U256::default(),
            difficulty: U256::default(),
            total_difficulty: 0.into(),
            base_fee_per_gas: None,
            uncles: vec![],
            transactions: BlockTransactions::Hashes(vec![].into()),
            size: 69.into(),
            nonce: H64::default(),
            mix_hash: H256::default(),
        };
        let serialized_block = serde_json::to_string(&block).unwrap();

        assert_eq!(
            serialized_block,
            r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","sha3Uncles":"0x0000000000000000000000000000000000000000000000000000000000000000","author":"0x0000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","number":"0x0","gasUsed":"0x0","gasLimit":"0x0","espaceGasLimit":"0x0","extraData":"0x","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x0","difficulty":"0x0","totalDifficulty":"0x0","uncles":[],"transactions":[],"size":"0x45","nonce":"0x0000000000000000","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}"#
        );
    }
}
