// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{Receipt, Transaction, H160, H256, U256};
use cfxcore::consensus::ConsensusGraphInner;
use jsonrpc_core::Error as RpcError;
use primitives::{
    receipt::{TRANSACTION_OUTCOME_EXCEPTION, TRANSACTION_OUTCOME_SUCCESS},
    Block as PrimitiveBlock, BlockHeaderBuilder, StateRootWithAuxInfo,
    TransactionAddress,
};
use serde::{
    de::{Deserialize, Deserializer, Error, Unexpected},
    Serialize, Serializer,
};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[derive(PartialEq, Debug)]
pub enum BlockTransactions {
    /// Only hashes
    Hashes(Vec<H256>),
    /// Full transactions
    Full(Vec<Transaction>),
}

//impl BlockTransactions {
//    pub fn new(
//        transactions: &Vec<Arc<SignedTransaction>>, include_txs: bool,
//        consensus_inner: &mut ConsensusGraphInner,
//    ) -> Self
//    {
//        match include_txs {
//            false => BlockTransactions::Hashes(
//                transactions.iter().map(|x| H256::from(x.hash())).collect(),
//            ),
//            true => BlockTransactions::Full(
//                transactions
//                    .iter()
//                    .map(|x| {
//                        Transaction::from_signed(
//                            x,
//                            consensus_inner
//                                .transaction_address_by_hash(&x.hash, false),
//                        )
//                    })
//                    .collect(),
//            ),
//        }
//    }
//}

impl Serialize for BlockTransactions {
    fn serialize<S: Serializer>(
        &self, serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match *self {
            BlockTransactions::Hashes(ref hashes) => {
                hashes.serialize(serializer)
            }
            BlockTransactions::Full(ref txs) => txs.serialize(serializer),
        }
    }
}

impl<'a> Deserialize<'a> for BlockTransactions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'a> {
        let value = Value::deserialize(deserializer)?;
        if let Value::Array(vec) = value {
            if vec.is_empty() {
                return Ok(BlockTransactions::Full(vec![]));
            }
            if let Value::String(_) = vec[0] {
                let mut result = vec![];
                for serialized_hash in vec {
                    let hash = H256::deserialize(serialized_hash)
                        .map_err(Error::custom)?;
                    result.push(hash);
                }
                return Ok(BlockTransactions::Hashes(result));
            } else {
                let mut result = vec![];
                for serialized_tx in vec {
                    let tx = Transaction::deserialize(serialized_tx)
                        .map_err(Error::custom)?;
                    result.push(tx);
                }
                return Ok(BlockTransactions::Full(result));
            }
        }
        Err(<D::Error as Error>::invalid_type(
            Unexpected::Other("not array"),
            &"array",
        ))
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    /// Hash of the block
    pub hash: H256,
    /// Hash of the parent
    pub parent_hash: H256,
    /// Distance to genesis
    pub height: U256,
    /// Author's address
    pub miner: H160,
    /// State root hash
    pub deferred_state_root: StateRootWithAuxInfo,
    /// Receipts root hash
    pub deferred_receipts_root: H256,
    /// Transactions root hash
    pub transactions_root: H256,
    /// Epoch number
    pub epoch_number: Option<U256>,
    /// Gas limit
    pub gas_limit: U256,
    /// Timestamp
    pub timestamp: U256,
    /// Difficulty
    pub difficulty: U256,
    /// Referee hashes
    pub referee_hashes: Vec<H256>,
    /// Stable
    pub stable: Option<bool>,
    /// Adaptive
    pub adaptive: bool,
    /// Nonce of the block
    pub nonce: U256,
    /// Transactions
    pub transactions: BlockTransactions,
    /// Size in bytes
    pub size: Option<U256>,
}

impl Block {
    pub fn new(
        b: &PrimitiveBlock, consensus_inner: &mut ConsensusGraphInner,
        include_txs: bool,
    ) -> Self
    {
        let transactions = match include_txs {
            false => BlockTransactions::Hashes(
                b.transactions
                    .iter()
                    .map(|x| H256::from(x.hash()))
                    .collect(),
            ),
            true => {
                let tx_vec = match consensus_inner
                    .block_receipts_by_hash(&b.hash(), false)
                {
                    Some(receipts) => b
                        .transactions
                        .iter()
                        .enumerate()
                        .map(|(idx, tx)| {
                            let receipt = receipts.get(idx).unwrap();
                            match receipt.outcome_status {
                                TRANSACTION_OUTCOME_SUCCESS => {
                                    Transaction::from_signed(
                                        tx,
                                        Some(Receipt::new(
                                            (**tx).clone(),
                                            receipt.clone(),
                                            TransactionAddress {
                                                block_hash: b.hash(),
                                                index: idx,
                                            },
                                        )),
                                    )
                                }
                                TRANSACTION_OUTCOME_EXCEPTION => {
                                    Transaction::from_signed(tx, None)
                                }
                                _ => {
                                    unreachable!();
                                }
                            }
                        })
                        .collect(),
                    None => b
                        .transactions
                        .iter()
                        .map(|x| Transaction::from_signed(x, None))
                        .collect(),
                };
                BlockTransactions::Full(tx_vec)
            }
        };
        Block {
            hash: H256::from(b.block_header.hash().clone()),
            parent_hash: H256::from(b.block_header.parent_hash().clone()),
            height: b.block_header.height().into(),
            miner: H160::from(b.block_header.author().clone()),
            deferred_state_root: b
                .block_header
                .deferred_state_root_with_aux_info()
                .into(),
            deferred_receipts_root: H256::from(
                b.block_header.deferred_receipts_root().clone(),
            ),
            transactions_root: H256::from(
                b.block_header.transactions_root().clone(),
            ),
            // PrimitiveBlock does not contain this information
            epoch_number: consensus_inner
                .get_block_epoch_number(&b.block_header.hash())
                .map_or(None, |x| match x {
                    std::usize::MAX => None,
                    _ => Some(x.into()),
                }),
            // fee system
            gas_limit: b.block_header.gas_limit().into(),
            timestamp: b.block_header.timestamp().into(),
            difficulty: b.block_header.difficulty().clone().into(),
            // PrimitiveBlock does not contain this information
            stable: consensus_inner.is_stable(&b.block_header.hash()),
            adaptive: b.block_header.adaptive(),
            referee_hashes: b
                .block_header
                .referee_hashes()
                .iter()
                .map(|x| H256::from(*x))
                .collect(),
            nonce: b.block_header.nonce().into(),
            transactions,
            size: Some(b.size().into()),
        }
    }

    pub fn into_primitive(self) -> Result<PrimitiveBlock, RpcError> {
        match self.transactions {
            BlockTransactions::Hashes(_) => Err(RpcError::invalid_params(
                "Invalid params: expected a array of transaction objects.",
            )),
            BlockTransactions::Full(vec) => Ok(PrimitiveBlock::new(
                BlockHeaderBuilder::new()
                    .with_parent_hash(self.parent_hash.into())
                    .with_height(self.height.as_usize() as u64)
                    .with_timestamp(self.timestamp.as_usize() as u64)
                    .with_author(self.miner.into())
                    .with_transactions_root(self.transactions_root.into())
                    .with_deferred_state_root(self.deferred_state_root.clone())
                    .with_deferred_receipts_root(
                        self.deferred_receipts_root.into(),
                    )
                    .with_difficulty(self.difficulty.into())
                    .with_adaptive(self.adaptive)
                    .with_gas_limit(self.gas_limit.into())
                    .with_referee_hashes(
                        self.referee_hashes
                            .iter()
                            .map(|x| x.clone().into())
                            .collect(),
                    )
                    .with_nonce(self.nonce.as_usize() as u64)
                    .build(),
                {
                    let mut transactions = Vec::new();
                    for tx in vec.into_iter() {
                        let signed_tx = tx.into_signed().map_err(|e| {
                            RpcError::invalid_params(format!("Invalid params: failed to convert from a rpc transaction to signed transaction {:?}", e))
                        })?;
                        transactions.push(Arc::new(signed_tx));
                    }
                    transactions
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Block, BlockTransactions};
    use crate::rpc::types::{Transaction, H160, H256, U256};
    use keccak_hash::KECCAK_NULL_RLP;
    use serde_json;

    #[test]
    fn test_serialize_block_transactions() {
        let t = BlockTransactions::Full(vec![Transaction::default()]);
        let serialized = serde_json::to_string(&t).unwrap();
        assert_eq!(serialized, r#"[{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","blockHash":null,"transactionIndex":null,"from":"0x0000000000000000000000000000000000000000","to":null,"value":"0x0","gasPrice":"0x0","gas":"0x0","contractCreated":null,"data":"0x","v":"0x0","r":"0x0","s":"0x0"}]"#);

        let t = BlockTransactions::Hashes(vec![H256::default().into()]);
        let serialized = serde_json::to_string(&t).unwrap();
        assert_eq!(serialized, r#"["0x0000000000000000000000000000000000000000000000000000000000000000"]"#);
    }

    #[test]
    fn test_deserialize_block_transactions() {
        let result_block_transactions = BlockTransactions::Hashes(vec![
            H256::default().into(),
            H256::default().into(),
        ]);
        let serialized = r#"["0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000"]"#;
        let deserialized_block_transactions: BlockTransactions =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(result_block_transactions, deserialized_block_transactions);

        let result_block_transactions =
            BlockTransactions::Full(vec![Transaction::default()]);
        let serialized = r#"[{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","blockHash":null,"blockNumber":null,"transactionIndex":null,"from":"0x0000000000000000000000000000000000000000","to":null,"value":"0x0","gasPrice":"0x0","gas":"0x0","data":"0x","v":"0x0","r":"0x0","s":"0x0"}]"#;
        let deserialized_block_transactions: BlockTransactions =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(result_block_transactions, deserialized_block_transactions);
    }

    #[test]
    fn test_serialize_block() {
        let block = Block {
            hash: H256::default(),
            parent_hash: H256::default(),
            height: 0.into(),
            miner: H160::default(),
            deferred_state_root: Default::default(),
            deferred_receipts_root: KECCAK_NULL_RLP.into(),
            transactions_root: KECCAK_NULL_RLP.into(),
            epoch_number: None,
            gas_limit: U256::default(),
            timestamp: 0.into(),
            difficulty: U256::default(),
            referee_hashes: Vec::new(),
            stable: None,
            adaptive: false,
            nonce: 0.into(),
            transactions: BlockTransactions::Hashes(vec![].into()),
            size: Some(69.into()),
        };
        let serialized_block = serde_json::to_string(&block).unwrap();

        assert_eq!(serialized_block, r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","height":"0x0","miner":"0x0000000000000000000000000000000000000000","deferredStateRoot":{"state_root":{"snapshot_root":"0x0000000000000000000000000000000000000000000000000000000000000000","intermediate_delta_root":"0x0000000000000000000000000000000000000000000000000000000000000000","delta_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"aux_info":{"previous_snapshot_root":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","intermediate_delta_epoch_id":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"}},"deferredReceiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","epochNumber":null,"gasLimit":"0x0","timestamp":"0x0","difficulty":"0x0","refereeHashes":[],"stable":null,"adaptive":false,"nonce":"0x0","transactions":[],"size":"0x45"}"#);
    }

    #[test]
    fn test_deserialize_block() {
        let serialized = r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","height":"0x0","miner":"0x0000000000000000000000000000000000000000","deferredStateRoot":{"state_root":{"snapshot_root":"0x0000000000000000000000000000000000000000000000000000000000000000","intermediate_delta_root":"0x0000000000000000000000000000000000000000000000000000000000000000","delta_root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"aux_info":{"previous_snapshot_root":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","intermediate_delta_epoch_id":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"}},"deferredReceiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","epochNumber":"0x0","gasLimit":"0x0","timestamp":"0x0","difficulty":"0x0","refereeHashes":[],"stable":null,"adaptive":false,"nonce":"0x0","transactions":[],"size":"0x45"}"#;
        let result_block = Block {
            hash: H256::default(),
            parent_hash: H256::default(),
            height: 0.into(),
            miner: H160::default(),
            deferred_state_root: Default::default(),
            deferred_receipts_root: KECCAK_NULL_RLP.into(),
            transactions_root: KECCAK_NULL_RLP.into(),
            epoch_number: Some(0.into()),
            gas_limit: U256::default(),
            timestamp: 0.into(),
            difficulty: U256::default(),
            referee_hashes: Vec::new(),
            stable: None,
            adaptive: false,
            nonce: 0.into(),
            transactions: BlockTransactions::Full(vec![].into()),
            size: Some(69.into()),
        };
        let deserialized_block: Block =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_block, result_block);
    }
}
