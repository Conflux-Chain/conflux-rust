use super::super::ConsensusGraph;

use crate::{
    block_data_manager::BlockExecutionResultWithEpoch,
    errors::Result as CoreResult,
};
use cfx_execute_helper::estimation::{EstimateExt, EstimateRequest};
use cfx_executor::{executive::ExecutionOutcome, state::State};
use cfx_parameters::rpc::{
    GAS_PRICE_BLOCK_SAMPLE_SIZE, GAS_PRICE_DEFAULT_VALUE,
    GAS_PRICE_TRANSACTION_SAMPLE_SIZE,
};
use cfx_rpc_eth_types::EvmOverrides;
use cfx_types::{Space, H256, U256};
use primitives::{
    receipt::{BlockReceipts, BlockReturnDatas},
    Block, EpochNumber, SignedTransaction,
};
use std::sync::Arc;

impl ConsensusGraph {
    /// Get the average gas price of the last GAS_PRICE_TRANSACTION_SAMPLE_SIZE
    /// blocks
    pub fn gas_price(&self, space: Space) -> Option<U256> {
        let inner = self.inner.read();
        let mut last_epoch_number = inner.best_epoch_number();
        let (
            number_of_tx_to_sample,
            mut number_of_blocks_to_sample,
            block_gas_ratio,
        ) = (
            GAS_PRICE_TRANSACTION_SAMPLE_SIZE,
            GAS_PRICE_BLOCK_SAMPLE_SIZE,
            1,
        );
        let mut prices = Vec::new();
        let mut total_block_gas_limit: u64 = 0;
        let mut total_tx_gas_limit: u64 = 0;

        loop {
            if number_of_blocks_to_sample == 0 || last_epoch_number == 0 {
                break;
            }
            if prices.len() == number_of_tx_to_sample {
                break;
            }
            let mut hashes = inner
                .block_hashes_by_epoch(last_epoch_number.into())
                .unwrap();
            hashes.reverse();
            last_epoch_number -= 1;

            for hash in hashes {
                let block = self
                    .data_man
                    .block_by_hash(&hash, false /* update_cache */)
                    .unwrap();
                total_block_gas_limit +=
                    block.block_header.gas_limit().as_u64() * block_gas_ratio;
                for tx in block.transactions.iter() {
                    if space == Space::Native && tx.space() != Space::Native {
                        // For cfx_gasPrice, we only count Native transactions.
                        continue;
                    }
                    // add the tx.gas() to total_tx_gas_limit even it is packed
                    // multiple times because these tx all
                    // will occupy block's gas space
                    total_tx_gas_limit += tx.transaction.gas().as_u64();
                    prices.push(tx.gas_price().clone());
                    if prices.len() == number_of_tx_to_sample {
                        break;
                    }
                }
                number_of_blocks_to_sample -= 1;
                if number_of_blocks_to_sample == 0
                    || prices.len() == number_of_tx_to_sample
                {
                    break;
                }
            }
        }

        prices.sort();
        if prices.is_empty() || total_tx_gas_limit == 0 {
            Some(U256::from(GAS_PRICE_DEFAULT_VALUE))
        } else {
            let average_gas_limit_multiple =
                total_block_gas_limit / total_tx_gas_limit;
            if average_gas_limit_multiple > 5 {
                // used less than 20%
                Some(U256::from(GAS_PRICE_DEFAULT_VALUE))
            } else if average_gas_limit_multiple >= 2 {
                // used less than 50%
                Some(prices[prices.len() / 8])
            } else {
                // used more than 50%
                Some(prices[prices.len() / 2])
            }
        }
    }

    pub fn get_block_execution_info(
        &self, block_hash: &H256,
    ) -> Option<(BlockExecutionResultWithEpoch, Option<H256>)> {
        let results_with_epoch = self
            .inner
            .read_recursive()
            .block_execution_results_by_hash(block_hash, true)?;

        let pivot_hash = results_with_epoch.0;

        let maybe_state_root = match self.executor.wait_for_result(pivot_hash) {
            Ok(execution_commitment) => {
                // We already has transaction address with epoch_hash executed,
                // so we can always get the state_root with
                // `wait_for_result`
                Some(
                    execution_commitment
                        .state_root_with_aux_info
                        .aux_info
                        .state_root_hash,
                )
            }
            Err(msg) => {
                warn!("get_transaction_receipt_and_block_info() gets the following error from ConsensusExecutor: {}", msg);
                None
            }
        };

        Some((results_with_epoch, maybe_state_root))
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch: EpochNumber,
        request: EstimateRequest, evm_overrides: EvmOverrides,
    ) -> CoreResult<(ExecutionOutcome, EstimateExt)> {
        // only allow to call against stated epoch
        self.validate_stated_epoch(&epoch)?;
        let (epoch_id, epoch_size) = if let Ok(v) =
            self.get_block_hashes_by_epoch(epoch)
        {
            (v.last().expect("pivot block always exist").clone(), v.len())
        } else {
            bail!("cannot get block hashes in the specified epoch, maybe it does not exist?");
        };
        self.executor.call_virtual(
            tx,
            &epoch_id,
            epoch_size,
            request,
            evm_overrides,
        )
    }

    // virtual execution results for epoch blocks
    pub fn collect_blocks_exec_result(
        &self, state: &mut State, blocks: &Vec<Arc<Block>>,
        trace_cfx_transfers: bool, start_block_number: u64,
    ) -> CoreResult<(Vec<Arc<BlockReceipts>>, Vec<BlockReturnDatas>)> {
        let _ = trace_cfx_transfers;
        self.executor.collect_blocks_exec_result(
            state,
            blocks,
            start_block_number,
        )
    }
}
