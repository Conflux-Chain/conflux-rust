use cfx_execute_helper::{
    exec_tracer::recover_phantom_traces,
    phantom_tx::build_bloom_and_recover_phantom,
};
use cfx_rpc_cfx_types::PhantomBlock;
use cfx_types::{Bloom, Space, H256, U256};
use cfxcore_errors::ProviderBlockError;
use primitives::{receipt::Receipt, EpochNumber, TransactionStatus};
use std::sync::Arc;

use super::super::ConsensusGraph;

impl ConsensusGraph {
    pub fn get_phantom_block_bloom_filter(
        &self, block_num: EpochNumber, pivot_assumption: H256,
    ) -> Result<Option<Bloom>, ProviderBlockError> {
        let hashes = self.get_block_hashes_by_epoch(block_num)?;

        // sanity check: epoch is not empty
        let pivot = match hashes.last() {
            Some(p) => p,
            None => return Err("Inconsistent state: empty epoch".into()),
        };

        if *pivot != pivot_assumption {
            return Ok(None);
        }

        // special handling for genesis block
        let genesis_hash = self.data_manager().true_genesis.hash();

        if hashes.last() == Some(&genesis_hash) {
            return Ok(Some(Bloom::zero()));
        }

        let mut bloom = Bloom::zero();

        for h in &hashes {
            let exec_info = match self
                .data_manager()
                .block_execution_result_by_hash_with_epoch(
                    h, pivot, false, // update_pivot_assumption
                    false, // update_cache
                ) {
                None => return Ok(None),
                Some(r) => r,
            };

            for receipt in exec_info.block_receipts.receipts.iter() {
                if receipt.outcome_status == TransactionStatus::Skipped {
                    continue;
                }

                // FIXME(thegaram): receipt does not contain `space`
                // so we combine blooms log by log.
                for log in &receipt.logs {
                    if log.space == Space::Ethereum {
                        bloom.accrue_bloom(&log.bloom());
                    }
                }
            }
        }

        Ok(Some(bloom))
    }

    pub fn get_phantom_block_pivot_by_number(
        &self, block_num: EpochNumber, pivot_assumption: Option<H256>,
        include_traces: bool,
    ) -> Result<Option<PhantomBlock>, ProviderBlockError> {
        self.get_phantom_block_by_number_inner(
            block_num,
            pivot_assumption,
            include_traces,
            true,
        )
    }

    pub fn get_phantom_block_by_number(
        &self, block_num: EpochNumber, pivot_assumption: Option<H256>,
        include_traces: bool,
    ) -> Result<Option<PhantomBlock>, ProviderBlockError> {
        self.get_phantom_block_by_number_inner(
            block_num,
            pivot_assumption,
            include_traces,
            false,
        )
    }

    fn get_phantom_block_by_number_inner(
        &self, block_num: EpochNumber, pivot_assumption: Option<H256>,
        include_traces: bool, only_pivot: bool,
    ) -> Result<Option<PhantomBlock>, ProviderBlockError> {
        let hashes = self.get_block_hashes_by_epoch(block_num)?;

        // special handling for genesis block
        let genesis = self.data_manager().true_genesis.clone();

        if hashes.last() == Some(&genesis.hash()) {
            return Ok(Some(PhantomBlock {
                pivot_header: genesis.block_header.clone(),
                transactions: vec![],
                receipts: vec![],
                errors: vec![],
                bloom: Bloom::zero(),
                traces: vec![],
                total_gas_limit: U256::from(0),
            }));
        }

        let blocks = match self
            .data_manager()
            .blocks_by_hash_list(&hashes, false /* update_cache */)
        {
            None => return Ok(None),
            Some(b) => b,
        };

        // sanity check: epoch is not empty
        let pivot = match blocks.last() {
            Some(p) => p,
            None => return Err("Inconsistent state: empty epoch".into()),
        };

        if matches!(pivot_assumption, Some(h) if h != pivot.hash()) {
            return Ok(None);
        }

        let mut phantom_block = PhantomBlock {
            pivot_header: pivot.block_header.clone(),
            transactions: vec![],
            receipts: vec![],
            errors: vec![],
            bloom: Default::default(),
            traces: vec![],
            total_gas_limit: U256::from(0),
        };

        let mut accumulated_gas_used = U256::from(0);
        let mut gas_used_offset;
        let mut total_gas_limit = U256::from(0);

        let iter_blocks = if only_pivot {
            &blocks[blocks.len() - 1..]
        } else {
            &blocks[..]
        };

        for b in iter_blocks {
            gas_used_offset = accumulated_gas_used;
            // note: we need the receipts to reconstruct a phantom block.
            // as a result, we cannot return unexecuted blocks in eth_* RPCs.
            let exec_info = match self
                .data_manager()
                .block_execution_result_by_hash_with_epoch(
                    &b.hash(),
                    &pivot.hash(),
                    false, // update_pivot_assumption
                    false, // update_cache
                ) {
                None => return Ok(None),
                Some(r) => r,
            };

            // note: we only include gas limit for blocks that will pack eSpace
            // tx(multiples of 5)
            total_gas_limit += b.block_header.espace_gas_limit(
                self.params
                    .can_pack_evm_transaction(b.block_header.height()),
            );

            let block_receipts = &exec_info.block_receipts.receipts;
            let errors = &exec_info.block_receipts.tx_execution_error_messages;

            let block_traces = if include_traces {
                match self.data_manager().block_tx_traces_by_hash(&b.hash()) {
                    None => {
                        return Err("Error while creating phantom block: state is ready but traces not found, did you enable 'executive_trace'?".into());
                    }
                    Some((pivot_hash, block_traces)) => {
                        // sanity check: transaction and trace length
                        if b.transactions.len() != block_traces.len() {
                            return Err("Inconsistent state: transactions and traces length mismatch".into());
                        }

                        // sanity check: no pivot reorg during processing
                        if pivot_hash != pivot.hash() {
                            return Err(
                                "Inconsistent state: pivot hash mismatch"
                                    .into(),
                            );
                        }

                        block_traces
                    }
                }
            } else {
                vec![]
            };

            // sanity check: transaction and receipt length
            if b.transactions.len() != block_receipts.len() {
                return Err("Inconsistent state: transactions and receipts length mismatch".into());
            }

            let evm_chain_id = self.best_chain_id().in_evm_space();

            for (id, tx) in b.transactions.iter().enumerate() {
                match tx.space() {
                    Space::Ethereum => {
                        let receipt = &block_receipts[id];

                        // we do not return non-executed transaction
                        if receipt.outcome_status == TransactionStatus::Skipped
                        {
                            continue;
                        }

                        phantom_block.transactions.push(tx.clone());

                        // sanity check: gas price must be positive
                        if *tx.gas_price() == 0.into() {
                            return Err("Inconsistent state: zero transaction gas price".into());
                        }

                        accumulated_gas_used =
                            gas_used_offset + receipt.accumulated_gas_used;

                        phantom_block.receipts.push(Receipt {
                            accumulated_gas_used,
                            outcome_status: receipt.outcome_status,
                            ..receipt.clone()
                        });

                        phantom_block.errors.push(errors[id].clone());
                        phantom_block.bloom.accrue_bloom(&receipt.log_bloom);

                        if include_traces {
                            phantom_block.traces.push(block_traces[id].clone());
                        }
                    }
                    Space::Native => {
                        // note: failing transactions will not produce any
                        // phantom txs or traces
                        if block_receipts[id].outcome_status
                            != TransactionStatus::Success
                        {
                            continue;
                        }

                        let (phantom_txs, _) = build_bloom_and_recover_phantom(
                            &block_receipts[id].logs[..],
                            tx.hash(),
                        );

                        if include_traces {
                            let tx_traces = block_traces[id].clone();

                            let phantom_traces =
                                recover_phantom_traces(tx_traces, tx.hash())?;

                            // sanity check: one trace for each phantom tx
                            if phantom_txs.len() != phantom_traces.len() {
                                error!("Inconsistent state: phantom tx and trace length mismatch, txs.len = {:?}, traces.len = {:?}", phantom_txs.len(), phantom_traces.len());
                                return Err("Inconsistent state: phantom tx and trace length mismatch".into());
                            }

                            phantom_block.traces.extend(phantom_traces);
                        }

                        for p in phantom_txs {
                            phantom_block.transactions.push(Arc::new(
                                p.clone().into_eip155(evm_chain_id),
                            ));

                            // note: phantom txs consume no gas
                            let phantom_receipt =
                                p.into_receipt(accumulated_gas_used);

                            phantom_block
                                .bloom
                                .accrue_bloom(&phantom_receipt.log_bloom);

                            phantom_block.receipts.push(phantom_receipt);

                            // note: phantom txs never fail
                            phantom_block.errors.push("".into());
                        }
                    }
                }
            }
        }

        phantom_block.total_gas_limit = total_gas_limit;
        Ok(Some(phantom_block))
    }

    pub fn get_phantom_block_by_hash(
        &self, hash: &H256, include_traces: bool,
    ) -> Result<Option<PhantomBlock>, ProviderBlockError> {
        let epoch_num = match self.get_block_epoch_number(hash) {
            None => return Ok(None),
            Some(n) => n,
        };

        self.get_phantom_block_by_number(
            EpochNumber::Number(epoch_num),
            Some(*hash),
            include_traces,
        )
    }
}
