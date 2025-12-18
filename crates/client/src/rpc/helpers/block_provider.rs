use crate::rpc::types::{
    cfx::{
        block::{Block, BlockTransactions, Header},
        transaction::PackedOrExecuted,
        RpcAddress,
    },
    Receipt, Transaction,
};
use cfx_addr::Network;
use cfx_types::{Space, H256, U256, U64};
use cfxcore::{
    block_data_manager::{BlockDataManager, DataVersionTuple},
    consensus::ConsensusGraphInner,
    pow, ConsensusGraph, SharedConsensusGraph,
};
use primitives::{
    Block as PrimitiveBlock, BlockHeader as PrimitiveBlockHeader,
    TransactionIndex, TransactionStatus,
};
use std::sync::Arc;

pub fn build_block(
    b: &PrimitiveBlock, network: Network, verbose: bool,
    consensus: &ConsensusGraph, consensus_inner: &ConsensusGraphInner,
    data_man: &Arc<BlockDataManager>, include_txs: bool,
    tx_space_filter: Option<Space>,
) -> Result<Block, String> {
    let block_hash = b.block_header.hash();

    let epoch_number = consensus_inner
        .get_block_epoch_number(&block_hash)
        .or_else(|| data_man.block_epoch_number(&block_hash))
        .map(Into::into);

    let block_number = consensus.get_block_number(&block_hash)?.map(Into::into);

    // get the block.gas_used
    let tx_len = b.transactions.len();

    let (gas_used, transactions) = {
        let maybe_results = consensus_inner.block_execution_results_by_hash(
            &b.hash(),
            false, /* update_cache */
        );

        // calculate block gasUsed according block.execution_result and
        // tx_space_filter
        let gas_used_sum = match maybe_results {
            Some(DataVersionTuple(_, ref execution_result)) => {
                match tx_space_filter {
                    Some(space_filter) => {
                        let mut total_gas_used = U256::zero();
                        let mut prev_acc_gas_used = U256::zero();
                        for (idx, tx) in b.transactions.iter().enumerate() {
                            let ref receipt =
                                execution_result.block_receipts.receipts[idx];
                            if tx.space() == space_filter {
                                total_gas_used += receipt.accumulated_gas_used
                                    - prev_acc_gas_used;
                            }
                            prev_acc_gas_used = receipt.accumulated_gas_used;
                        }
                        Some(total_gas_used)
                    }
                    None => Some(
                        execution_result.block_receipts.receipts[tx_len - 1]
                            .accumulated_gas_used,
                    ),
                }
            }
            None => None,
        };

        // prepare the transaction array according include_txs,
        // execution_result, tx_space_filter
        let transactions = match include_txs {
            false => BlockTransactions::Hashes(
                b.transaction_hashes(Some(Space::Native)),
            ),
            true => {
                let tx_vec = match maybe_results {
                    Some(DataVersionTuple(_, ref execution_result)) => {
                        let maybe_state_root =
                            data_man.get_executed_state_root(&b.hash());

                        b.transactions
                            .iter()
                            .enumerate()
                            .filter(|(_idx, tx)| {
                                tx_space_filter.is_none()
                                    || tx.space() == tx_space_filter.unwrap()
                            })
                            .enumerate()
                            .map(|(new_index, (original_index, tx))| {
                                let receipt = execution_result
                                    .block_receipts
                                    .receipts
                                    .get(original_index)
                                    .unwrap();
                                let prior_gas_used = if original_index == 0 {
                                    U256::zero()
                                } else {
                                    execution_result.block_receipts.receipts
                                        [original_index - 1]
                                        .accumulated_gas_used
                                };
                                match receipt.outcome_status {
                                    TransactionStatus::Success
                                    | TransactionStatus::Failure => {
                                        let tx_index = TransactionIndex {
                                            block_hash: b.hash(),
                                            real_index: original_index,
                                            is_phantom: false,
                                            rpc_index: Some(new_index),
                                        };
                                        let tx_exec_error_msg =
                                            &execution_result
                                                .block_receipts
                                                .tx_execution_error_messages
                                                [original_index];
                                        Transaction::from_signed(
                                            tx,
                                            Some(PackedOrExecuted::Executed(
                                                Receipt::new(
                                                    (**tx).clone(),
                                                    receipt.clone(),
                                                    tx_index,
                                                    prior_gas_used,
                                                    epoch_number,
                                                    execution_result
                                                        .block_receipts
                                                        .block_number,
                                                    b.block_header.base_price(),
                                                    maybe_state_root,
                                                    if tx_exec_error_msg
                                                        .is_empty()
                                                    {
                                                        None
                                                    } else {
                                                        Some(
                                                            tx_exec_error_msg
                                                                .clone(),
                                                        )
                                                    },
                                                    network,
                                                    verbose,
                                                    false,
                                                    false,
                                                )?,
                                            )),
                                            network,
                                            verbose,
                                        )
                                    }
                                    TransactionStatus::Skipped => {
                                        Transaction::from_signed(
                                            tx, None, network, verbose,
                                        )
                                    }
                                }
                            })
                            .collect::<Result<_, _>>()?
                    }
                    None => b
                        .transactions
                        .iter()
                        .filter(|tx| {
                            tx_space_filter.is_none()
                                || tx.space() == tx_space_filter.unwrap()
                        })
                        .map(|x| {
                            Transaction::from_signed(x, None, network, verbose)
                        })
                        .collect::<Result<_, _>>()?,
                };
                BlockTransactions::Full(tx_vec)
            }
        };

        (gas_used_sum, transactions)
    };

    let base_fee_per_gas: Option<U256> =
        b.block_header.base_price().map(|x| x[Space::Native]).into();

    // if a block is 1559 block(has base_fee_per_gas) then it's
    // block.gas_limit is 90% of the actual block.gas_limit
    let gas_limit: U256 = b.block_header.core_space_gas_limit();

    Ok(Block {
        hash: H256::from(block_hash),
        parent_hash: H256::from(b.block_header.parent_hash().clone()),
        height: b.block_header.height().into(),
        miner: RpcAddress::try_from_h160(
            *b.block_header.author(),
            network,
            verbose,
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
        epoch_number: epoch_number.map(|e| U256::from(e)),
        block_number,
        // fee system
        gas_used,
        gas_limit,
        base_fee_per_gas,
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
        custom: b
            .block_header
            .custom()
            .clone()
            .into_iter()
            .map(Into::into)
            .collect(),
        size: Some(b.size().into()),
        pos_reference: b.block_header.pos_reference().clone(),
    })
}

pub fn build_header(
    h: &PrimitiveBlockHeader, network: Network, verbose: bool,
    consensus: SharedConsensusGraph,
) -> Result<Header, String> {
    let hash = h.hash();

    let epoch_number = consensus
        .get_block_epoch_number(&hash)
        .or_else(|| consensus.data_manager().block_epoch_number(&hash))
        .map(Into::into);

    let block_number = consensus.get_block_number(&hash)?.map(Into::into);

    let base_fee_per_gas: Option<U256> =
        h.base_price().map(|x| x[Space::Native]).into();

    let referee_hashes =
        h.referee_hashes().iter().map(|x| H256::from(*x)).collect();

    Ok(Header {
        hash: H256::from(hash),
        parent_hash: H256::from(*h.parent_hash()),
        height: h.height().into(),
        miner: RpcAddress::try_from_h160(*h.author(), network, verbose)?,
        deferred_state_root: H256::from(*h.deferred_state_root()),
        deferred_receipts_root: H256::from(*h.deferred_receipts_root()),
        deferred_logs_bloom_hash: H256::from(*h.deferred_logs_bloom_hash()),
        blame: U64::from(h.blame()),
        transactions_root: H256::from(*h.transactions_root()),
        epoch_number,
        block_number,
        gas_limit: h.gas_limit().into(),
        base_fee_per_gas,
        timestamp: h.timestamp().into(),
        difficulty: h.difficulty().into(),
        adaptive: h.adaptive(),
        referee_hashes,
        nonce: h.nonce().into(),
        pow_quality: h
            .pow_hash
            .map(|pow_hash| pow::pow_hash_to_quality(&pow_hash, &h.nonce())),
        pos_reference: *h.pos_reference(),
        custom: h.custom().clone().into_iter().map(Into::into).collect(),
    })
}
