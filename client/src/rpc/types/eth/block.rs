// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{eth::Transaction, Bytes};
use cfx_types::{hexstr_to_h256, Bloom as H2048, Space, H160, H256, H64, U256};
use cfxcore::consensus::ConsensusGraphInner;
use primitives::Block as PrimitiveBlock;
use serde::{Serialize, Serializer};

const SHA3_HASH_OF_EMPTY_UNCLE: &str =
    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";

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
    pub fn new(
        blocks: Vec<&PrimitiveBlock>, full: bool,
        consensus_inner: &ConsensusGraphInner,
    ) -> Self
    {
        let mut gas_used = U256::zero();
        let mut logs_bloom = H2048::zero();

        let pivot = blocks.last().expect("Inconsistent state");

        for b in &blocks {
            let maybe_exec_res = consensus_inner
                .data_man
                .block_execution_result_by_hash_with_epoch(
                    &b.hash(),
                    &pivot.hash(),
                    false, // update_pivot_assumption
                    false, // update_cache
                );

            match maybe_exec_res {
                // we keep a lock on `inner` so pivot chain reorg should not
                // happen here, but it's possible the block is not executed yet
                None => {
                    gas_used = U256::zero();
                    logs_bloom = H2048::zero();
                    break;
                }
                Some(res) => {
                    gas_used += res
                        .block_receipts
                        .receipts
                        .last()
                        .map(|r| r.accumulated_gas_used)
                        .unwrap_or_default();

                    logs_bloom.accrue_bloom(&res.bloom);
                }
            }
        }

        Block {
            hash: pivot.block_header.hash(),
            parent_hash: pivot.block_header.parent_hash().clone(),
            uncles_hash: hexstr_to_h256(SHA3_HASH_OF_EMPTY_UNCLE),
            author: pivot.block_header.author().clone(),
            miner: pivot.block_header.author().clone(),
            state_root: pivot.block_header.deferred_state_root().clone(),
            transactions_root: pivot.block_header.transactions_root().clone(),
            receipts_root: pivot.block_header.deferred_receipts_root().clone(),
            // We use height to replace block number for ETH interface.
            // Note: this will correspond to the epoch number.
            number: pivot.block_header.height().into(),
            gas_used,
            gas_limit: pivot.block_header.gas_limit().into(),
            extra_data: Default::default(),
            logs_bloom,
            timestamp: pivot.block_header.timestamp().into(),
            difficulty: pivot.block_header.difficulty().into(),
            total_difficulty: 0.into(),
            base_fee_per_gas: None,
            uncles: vec![],
            // Note: we allow U256 nonce in Stratum and in the block.
            // However, most mining clients use U64. Here we truncate
            // to U64 to maintain compatibility with eth.
            nonce: pivot.block_header.nonce().low_u64().to_be_bytes().into(),
            mix_hash: H256::default(),
            // TODO(thegaram): include phantom txs
            transactions: if full {
                BlockTransactions::Full(
                    blocks
                        .iter()
                        .map(|b| &b.transactions)
                        .flatten()
                        .filter(|tx| tx.space() == Space::Ethereum)
                        .enumerate()
                        .map(|(idx, t)| {
                            Transaction::from_signed(
                                &**t,
                                (
                                    Some(pivot.block_header.hash()), // block_hash
                                    Some(pivot.block_header.height().into()), // block_number
                                    Some(idx.into()), // transaction_index
                                ),
                            )
                        })
                        .collect(),
                )
            } else {
                BlockTransactions::Hashes(
                    blocks
                        .iter()
                        .map(|b| {
                            b.transaction_hashes(Some(Space::Ethereum))
                                .into_iter()
                        })
                        .flatten()
                        .collect(),
                )
            },
            // FIXME(thegaram): should we recalculate size?
            size: blocks.iter().map(|b| b.size()).sum::<usize>().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Block, BlockTransactions};
    use crate::rpc::types::Bytes;
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

        assert_eq!(serialized_block, r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","sha3Uncles":"0x0000000000000000000000000000000000000000000000000000000000000000","author":"0x0000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","number":"0x0","gasUsed":"0x0","gasLimit":"0x0","extraData":"0x","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x0","difficulty":"0x0","totalDifficulty":"0x0","uncles":[],"transactions":[],"size":"0x45","nonce":"0x0000000000000000","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}"#);
    }
}
