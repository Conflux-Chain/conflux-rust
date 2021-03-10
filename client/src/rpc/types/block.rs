// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::RpcAddress;
use cfx_addr::Network;
use cfx_types::{H160, H256, U256, U64};
use cfxcore::{
    block_data_manager::{BlockDataManager, DataVersionTuple},
    consensus::ConsensusGraphInner,
    pow, SharedConsensusGraph,
};
use jsonrpc_core::Error as RpcError;
use primitives::{
    receipt::{
        TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING,
        TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING,
        TRANSACTION_OUTCOME_SUCCESS,
    },
    Block as PrimitiveBlock, BlockHeader as PrimitiveBlockHeader,
    BlockHeaderBuilder, TransactionIndex,
};
use serde::{
    de::{Deserialize, Deserializer, Error, Unexpected},
    Serialize, Serializer,
};
use serde_json::Value;
use std::{convert::TryInto, sync::Arc};

use crate::rpc::types::{transaction::PackedOrExecuted, Receipt, Transaction};
use cfx_bytes::Bytes;

#[derive(PartialEq, Debug)]
pub enum BlockTransactions {
    /// Only hashes
    Hashes(Vec<H256>),
    /// Full transactions
    Full(Vec<Transaction>),
}

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
    where
        D: Deserializer<'a>,
    {
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
    pub miner: RpcAddress,
    /// State root hash
    pub deferred_state_root: H256,
    /// Root hash of all receipts in this block's epoch
    pub deferred_receipts_root: H256,
    /// Hash of aggregated bloom filter of all receipts in this block's epoch
    pub deferred_logs_bloom_hash: H256,
    /// Blame indicates the number of ancestors whose
    /// state_root/receipts_root/logs_bloom_hash/blame are not correct.
    /// It acts as a vote to help light client determining the
    /// state_root/receipts_root/logs_bloom_hash are correct or not.
    pub blame: U64,
    /// Transactions root hash
    pub transactions_root: H256,
    /// Epoch number
    pub epoch_number: Option<U256>,
    /// Gas limit
    pub gas_limit: U256,
    /// Gas used
    pub gas_used: Option<U256>,
    /// Timestamp
    pub timestamp: U256,
    /// Difficulty
    pub difficulty: U256,
    // TODO: We should change python test script and remove this field
    /// PoW Quality
    pub pow_quality: Option<U256>,
    /// Referee hashes
    pub referee_hashes: Vec<H256>,
    /// Adaptive
    pub adaptive: bool,
    /// Nonce of the block
    pub nonce: U256,
    /// Transactions
    pub transactions: BlockTransactions,
    /// Size in bytes
    pub size: Option<U256>,
    /// Custom field
    pub custom: Vec<Bytes>,
}

impl Block {
    pub fn new(
        b: &PrimitiveBlock, network: Network,
        consensus_inner: &ConsensusGraphInner,
        data_man: &Arc<BlockDataManager>, include_txs: bool,
    ) -> Result<Self, String> {
        let transactions = match include_txs {
            false => BlockTransactions::Hashes(
                b.transactions
                    .iter()
                    .map(|x| H256::from(x.hash()))
                    .collect(),
            ),
            true => {
                let tx_vec = match consensus_inner
                    .block_execution_results_by_hash(
                        &b.hash(),
                        false, /* update_cache */
                    ) {
                    Some(DataVersionTuple(_, execution_result)) => {
                        let epoch_number =
                            consensus_inner.get_block_epoch_number(&b.hash());

                        let maybe_state_root =
                            data_man.get_executed_state_root(&b.hash());

                        b.transactions
                        .iter()
                        .enumerate()
                        .map(|(idx, tx)| {
                            let receipt = execution_result.block_receipts.receipts.get(idx).unwrap();
                            let prior_gas_used = if idx == 0 {
                                 U256::zero()
                            } else {
                                execution_result.block_receipts.receipts[idx - 1].accumulated_gas_used
                            };
                            match receipt.outcome_status {
                                TRANSACTION_OUTCOME_SUCCESS
                                | TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING => {
                                    let tx_index = TransactionIndex {
                                        block_hash: b.hash(),
                                        index: idx,
                                    };
                                    let tx_exec_error_msg = &execution_result.block_receipts.tx_execution_error_messages[idx];
                                    Transaction::from_signed(
                                        tx,
                                        Some(PackedOrExecuted::Executed(Receipt::new(
                                            (**tx).clone(),
                                            receipt.clone(),
                                            tx_index,
                                            prior_gas_used,
                                            epoch_number,
                                            execution_result.block_receipts.block_number,
                                            maybe_state_root,
                                            if tx_exec_error_msg.is_empty() {
                                                None
                                            } else {
                                                Some(tx_exec_error_msg.clone())
                                            },
                                            network,
                                        )?)),
                                        network,
                                    )
                                }
                                TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING => {
                                    Transaction::from_signed(tx, None, network)
                                }
                                _ => {
                                    unreachable!();
                                }
                            }
                        })
                        .collect::<Result<_, _>>()?
                    }
                    None => b
                        .transactions
                        .iter()
                        .map(|x| Transaction::from_signed(x, None, network))
                        .collect::<Result<_, _>>()?,
                };
                BlockTransactions::Full(tx_vec)
            }
        };

        let block_hash = b.block_header.hash();

        let epoch_number = consensus_inner
            .get_block_epoch_number(&block_hash)
            .or_else(|| data_man.block_epoch_number(&block_hash))
            .map(Into::into);

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

        Ok(Block {
            hash: H256::from(block_hash),
            parent_hash: H256::from(b.block_header.parent_hash().clone()),
            height: b.block_header.height().into(),
            miner: RpcAddress::try_from_h160(
                *b.block_header.author(),
                network,
            )?,
            deferred_state_root: H256::from(
                b.block_header.deferred_state_root().clone(),
            ),
            deferred_receipts_root: H256::from(
                b.block_header.deferred_receipts_root().clone(),
            ),
            deferred_logs_bloom_hash: H256::from(
                b.block_header.deferred_logs_bloom_hash().clone(),
            ),
            blame: U64::from(b.block_header.blame()),
            transactions_root: H256::from(
                b.block_header.transactions_root().clone(),
            ),
            // PrimitiveBlock does not contain this information
            epoch_number,
            // fee system
            gas_used,
            gas_limit: b.block_header.gas_limit().into(),
            timestamp: b.block_header.timestamp().into(),
            difficulty: b.block_header.difficulty().clone().into(),
            pow_quality: b
                .block_header
                .pow_hash
                .map(|h| pow::pow_hash_to_quality(&h, &b.block_header.nonce())),
            adaptive: b.block_header.adaptive(),
            referee_hashes: b
                .block_header
                .referee_hashes()
                .iter()
                .map(|x| H256::from(*x))
                .collect(),
            nonce: b.block_header.nonce().into(),
            transactions,
            custom: b.block_header.custom().clone(),
            size: Some(b.size().into()),
        })
    }

    pub fn into_primitive(self) -> Result<PrimitiveBlock, RpcError> {
        let miner: H160 = match self.miner.try_into() {
            Ok(m) => m,
            Err(_) => bail!(RpcError::invalid_params(
                "Invalid params: expected a valid base32-encoded Conflux address",
            )),
        };

        match self.transactions {
            BlockTransactions::Hashes(_) => Err(RpcError::invalid_params(
                "Invalid params: expected a array of transaction objects.",
            )),
            BlockTransactions::Full(vec) => Ok(PrimitiveBlock::new(
                BlockHeaderBuilder::new()
                    .with_parent_hash(self.parent_hash.into())
                    .with_height(self.height.as_usize() as u64)
                    .with_timestamp(self.timestamp.as_usize() as u64)
                    .with_author(miner)
                    .with_transactions_root(self.transactions_root.into())
                    .with_deferred_state_root(self.deferred_state_root.into())
                    .with_deferred_receipts_root(
                        self.deferred_receipts_root.into(),
                    )
                    .with_deferred_logs_bloom_hash(
                        self.deferred_logs_bloom_hash.into(),
                    )
                    .with_blame(self.blame.as_u32())
                    .with_difficulty(self.difficulty.into())
                    .with_adaptive(self.adaptive)
                    .with_gas_limit(self.gas_limit.into())
                    .with_referee_hashes(
                        self.referee_hashes
                            .iter()
                            .map(|x| x.clone().into())
                            .collect(),
                    )
                    .with_nonce(self.nonce.into())
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

/// Block header representation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Hash of the block
    pub hash: H256,
    /// Hash of the parent
    pub parent_hash: H256,
    /// Distance to genesis
    pub height: U256,
    /// Miner's address
    pub miner: RpcAddress,
    /// State root hash
    pub deferred_state_root: H256,
    /// Root hash of all receipts in this block's epoch
    pub deferred_receipts_root: H256,
    /// Hash of aggregrated bloom filter of all receipts in the block's epoch
    pub deferred_logs_bloom_hash: H256,
    /// Blame indicates the number of ancestors whose
    /// state_root/receipts_root/logs_bloom_hash/blame are not correct.
    /// It acts as a vote to help light client determining the
    /// state_root/receipts_root/logs_bloom_hash are correct or not.
    pub blame: U64,
    /// Transactions root hash
    pub transactions_root: H256,
    /// Epoch number
    pub epoch_number: Option<U256>,
    /// Gas Limit
    pub gas_limit: U256,
    /// Timestamp
    pub timestamp: U256,
    /// Difficulty
    pub difficulty: U256,
    // TODO: We should change python test script and remove this field
    /// PoW Quality
    pub pow_quality: Option<U256>,
    /// Referee hashes
    pub referee_hashes: Vec<H256>,
    /// Adaptive
    pub adaptive: bool,
    /// Nonce of the block
    pub nonce: U256,
}

impl Header {
    pub fn new(
        h: &PrimitiveBlockHeader, network: Network,
        consensus: SharedConsensusGraph,
    ) -> Result<Self, String> {
        let hash = h.hash();

        let epoch_number = consensus
            .get_block_epoch_number(&hash)
            .or_else(|| consensus.get_data_manager().block_epoch_number(&hash))
            .map(Into::into);

        let referee_hashes =
            h.referee_hashes().iter().map(|x| H256::from(*x)).collect();

        Ok(Header {
            hash: H256::from(hash),
            parent_hash: H256::from(*h.parent_hash()),
            height: h.height().into(),
            miner: RpcAddress::try_from_h160(*h.author(), network)?,
            deferred_state_root: H256::from(*h.deferred_state_root()),
            deferred_receipts_root: H256::from(*h.deferred_receipts_root()),
            deferred_logs_bloom_hash: H256::from(*h.deferred_logs_bloom_hash()),
            blame: U64::from(h.blame()),
            transactions_root: H256::from(*h.transactions_root()),
            epoch_number,
            gas_limit: h.gas_limit().into(),
            timestamp: h.timestamp().into(),
            difficulty: h.difficulty().into(),
            adaptive: h.adaptive(),
            referee_hashes,
            nonce: h.nonce().into(),
            pow_quality: h.pow_hash.map(|pow_hash| {
                pow::pow_hash_to_quality(&pow_hash, &h.nonce())
            }), /* TODO(thegaram):
                 * include custom */
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Block, BlockTransactions, Header, RpcAddress};
    use crate::rpc::types::Transaction;
    use cfx_addr::Network;
    use cfx_types::{H256, U256};
    use keccak_hash::KECCAK_EMPTY_LIST_RLP;
    use serde_json;
    use serial_test::serial;

    #[test]
    fn test_serialize_block_transactions() {
        let t =
            BlockTransactions::Full(vec![
                Transaction::default(Network::Main).unwrap()
            ]);
        let serialized = serde_json::to_string(&t).unwrap();
        assert_eq!(
            serialized,
            r#"[{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","blockHash":null,"transactionIndex":null,"from":"CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2","to":null,"value":"0x0","gasPrice":"0x0","gas":"0x0","contractCreated":null,"data":"0x","storageLimit":"0x0","epochHeight":"0x0","chainId":"0x0","status":null,"v":"0x0","r":"0x0","s":"0x0"}]"#
        );

        let t = BlockTransactions::Hashes(vec![H256::default()]);
        let serialized = serde_json::to_string(&t).unwrap();
        assert_eq!(
            serialized,
            r#"["0x0000000000000000000000000000000000000000000000000000000000000000"]"#
        );
    }

    #[test]
    #[serial] // TODO: remove
    fn test_deserialize_block_transactions() {
        let result_block_transactions =
            BlockTransactions::Hashes(vec![H256::default(), H256::default()]);
        let serialized = r#"["0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000"]"#;
        let deserialized_block_transactions: BlockTransactions =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(result_block_transactions, deserialized_block_transactions);

        let result_block_transactions = BlockTransactions::Full(vec![
            Transaction::default(Network::Main).unwrap(),
        ]);
        let serialized = r#"[{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","blockHash":null,"blockNumber":null,"transactionIndex":null,"from":"CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2","to":null,"value":"0x0","gasPrice":"0x0","gas":"0x0","data":"0x","storageLimit":"0x0","epochHeight":"0x0","chainId":"0x0","status":null,"v":"0x0","r":"0x0","s":"0x0"}]"#;
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
            miner: RpcAddress::null(Network::Main).unwrap(),
            deferred_state_root: Default::default(),
            deferred_receipts_root: KECCAK_EMPTY_LIST_RLP.into(),
            deferred_logs_bloom_hash: cfx_types::KECCAK_EMPTY_BLOOM.into(),
            blame: 0.into(),
            transactions_root: KECCAK_EMPTY_LIST_RLP.into(),
            epoch_number: None,
            gas_limit: U256::default(),
            gas_used: None,
            timestamp: 0.into(),
            difficulty: U256::default(),
            pow_quality: None,
            referee_hashes: Vec::new(),
            adaptive: false,
            nonce: 0.into(),
            transactions: BlockTransactions::Hashes(vec![]),
            custom: vec![],
            size: Some(69.into()),
        };
        let serialized_block = serde_json::to_string(&block).unwrap();

        assert_eq!(
            serialized_block,
            r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","height":"0x0","miner":"CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2","deferredStateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","deferredReceiptsRoot":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","deferredLogsBloomHash":"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5","blame":"0x0","transactionsRoot":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","epochNumber":null,"gasLimit":"0x0","gasUsed":null,"timestamp":"0x0","difficulty":"0x0","powQuality":null,"refereeHashes":[],"adaptive":false,"nonce":"0x0","transactions":[],"size":"0x45","custom":[]}"#
        );
    }

    #[test]
    #[serial] // TODO: remove
    fn test_deserialize_block() {
        let serialized = r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","height":"0x0","miner":"CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2","deferredStateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","deferredReceiptsRoot":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","deferredLogsBloomHash":"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5","blame":"0x0","transactionsRoot":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","epochNumber":"0x0","gasLimit":"0x0","timestamp":"0x0","difficulty":"0x0","refereeHashes":[],"stable":null,"adaptive":false,"nonce":"0x0","transactions":[],"size":"0x45","custom":[]}"#;
        let result_block = Block {
            hash: H256::default(),
            parent_hash: H256::default(),
            height: 0.into(),
            miner: RpcAddress::null(Network::Main).unwrap(),
            deferred_state_root: Default::default(),
            deferred_receipts_root: KECCAK_EMPTY_LIST_RLP.into(),
            deferred_logs_bloom_hash: cfx_types::KECCAK_EMPTY_BLOOM.into(),
            blame: 0.into(),
            transactions_root: KECCAK_EMPTY_LIST_RLP.into(),
            epoch_number: Some(0.into()),
            gas_limit: U256::default(),
            gas_used: None,
            timestamp: 0.into(),
            difficulty: U256::default(),
            pow_quality: None,
            referee_hashes: Vec::new(),
            adaptive: false,
            nonce: 0.into(),
            transactions: BlockTransactions::Full(vec![]),
            custom: vec![],
            size: Some(69.into()),
        };
        let deserialized_block: Block =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_block, result_block);
    }

    #[test]
    fn test_serialize_header() {
        let header = Header {
            hash: H256::default(),
            parent_hash: H256::default(),
            height: 0.into(),
            miner: RpcAddress::null(Network::Main).unwrap(),
            deferred_state_root: Default::default(),
            deferred_receipts_root: KECCAK_EMPTY_LIST_RLP.into(),
            deferred_logs_bloom_hash: cfx_types::KECCAK_EMPTY_BLOOM.into(),
            blame: 0.into(),
            transactions_root: KECCAK_EMPTY_LIST_RLP.into(),
            epoch_number: None,
            gas_limit: U256::default(),
            timestamp: 0.into(),
            difficulty: U256::default(),
            pow_quality: None,
            referee_hashes: Vec::new(),
            adaptive: false,
            nonce: 0.into(),
        };
        let serialized_header = serde_json::to_string(&header).unwrap();

        assert_eq!(
            serialized_header,
            r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","height":"0x0","miner":"CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2","deferredStateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","deferredReceiptsRoot":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","deferredLogsBloomHash":"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5","blame":"0x0","transactionsRoot":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","epochNumber":null,"gasLimit":"0x0","timestamp":"0x0","difficulty":"0x0","powQuality":null,"refereeHashes":[],"adaptive":false,"nonce":"0x0"}"#
        );
    }
}
