use cfx_types::{H256, U256};
use primitives::{
    receipt::Receipt, SignedTransaction, TransactionIndex, TransactionStatus,
};

use super::super::ConsensusGraph;

pub struct TransactionInfo {
    pub tx_index: TransactionIndex,
    pub maybe_executed_extra_info: Option<MaybeExecutedTxExtraInfo>,
}

pub struct MaybeExecutedTxExtraInfo {
    pub receipt: Receipt,
    pub block_number: u64,
    pub prior_gas_used: U256,
    pub tx_exec_error_msg: Option<String>,
}

impl ConsensusGraph {
    pub fn get_signed_tx_and_tx_info(
        &self, hash: &H256,
    ) -> Option<(SignedTransaction, TransactionInfo)> {
        // We need to hold the inner lock to ensure that tx_index and receipts
        // are consistent

        let tx_info = self.get_transaction_info(hash)?;
        if let Some(executed) = &tx_info.maybe_executed_extra_info {
            if executed.receipt.outcome_status == TransactionStatus::Skipped {
                // A skipped transaction is not visible to clients if
                // accessed by its hash.
                return None;
            }
        }
        let block = self.data_man.block_by_hash(
            &tx_info.tx_index.block_hash,
            false, /* update_cache */
        )?;
        let transaction =
            (*block.transactions[tx_info.tx_index.real_index]).clone();
        Some((transaction, tx_info))
    }

    fn get_transaction_info(&self, tx_hash: &H256) -> Option<TransactionInfo> {
        let inner = self.inner.read();

        trace!("Get receipt with tx_hash {}", tx_hash);
        let tx_index = self.data_man.transaction_index_by_hash(
            tx_hash, false, /* update_cache */
        )?;
        // receipts should never be None if transaction index isn't none.
        let maybe_executed_extra_info = inner
            .block_execution_results_by_hash(
                &tx_index.block_hash,
                false, /* update_cache */
            )
            .map(|receipt| {
                let block_receipts = receipt.1.block_receipts;

                let prior_gas_used = if tx_index.real_index == 0 {
                    U256::zero()
                } else {
                    block_receipts.receipts[tx_index.real_index - 1]
                        .accumulated_gas_used
                };
                let tx_exec_error_msg = block_receipts
                    .tx_execution_error_messages[tx_index.real_index]
                    .clone();

                MaybeExecutedTxExtraInfo {
                    receipt: block_receipts
                        .receipts
                        .get(tx_index.real_index)
                        .expect("Error: can't get receipt by tx_index ")
                        .clone(),
                    block_number: block_receipts.block_number,
                    prior_gas_used,
                    tx_exec_error_msg: if tx_exec_error_msg.is_empty() {
                        None
                    } else {
                        Some(tx_exec_error_msg.clone())
                    },
                }
            });

        Some(TransactionInfo {
            tx_index,
            maybe_executed_extra_info,
        })
    }
}
