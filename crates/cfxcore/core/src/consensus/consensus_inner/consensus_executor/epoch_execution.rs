use super::ConsensusExecutionHandler;
use std::{convert::From, sync::Arc};

use pow_types::StakingEvent;

use cfx_statedb::{ErrorKind as DbErrorKind, Result as DbResult};
use cfx_types::{Space, SpaceMap, H256, U256};
use primitives::{
    receipt::BlockReceipts, Action, Block, BlockNumber, EpochId, Receipt,
    SignedTransaction, TransactionIndex,
};

use crate::{
    block_data_manager::BlockDataManager,
    consensus::consensus_inner::consensus_executor::GOOD_TPS_METER,
    state_prefetcher::{prefetch_accounts, PrefetchTaskHandle},
};
use cfx_execute_helper::{
    exec_tracer::TransactionExecTraces,
    observer::Observer,
    tx_outcome::{make_process_tx_outcome, ProcessTxOutcome},
};
use cfx_executor::{
    executive::{ExecutiveContext, TransactOptions, TransactSettings},
    internal_contract::{
        block_hash_slot, epoch_hash_slot, initialize_internal_contract_accounts,
    },
    state::{
        initialize_cip107, initialize_cip137,
        initialize_or_update_dao_voted_params, State,
    },
};
use cfx_vm_types::Env;

impl ConsensusExecutionHandler {
    pub(super) fn process_epoch_transactions(
        &self, epoch_id: EpochId, state: &mut State,
        epoch_blocks: &Vec<Arc<Block>>, start_block_number: u64,
        on_local_pivot: bool,
    ) -> DbResult<Vec<Arc<BlockReceipts>>> {
        self.prefetch_storage_for_execution(epoch_id, state, epoch_blocks);

        let pivot_block = epoch_blocks.last().expect("Epoch not empty");

        self.before_epoch_execution(state, &*pivot_block)?;

        let base_gas_price = pivot_block
            .block_header
            .core_base_fee()
            .cloned()
            .unwrap_or_default();

        let burnt_gas_price = state.burnt_gas_price(base_gas_price);
        let context = EpochProcessContext {
            on_local_pivot,
            executive_trace: self.config.executive_trace,
            pivot_block,
            base_gas_price,
            burnt_gas_price,
        };

        let mut epoch_recorder = EpochProcessRecorder::new();

        let mut block_context = BlockProcessContext::first_block(
            &context,
            epoch_blocks.first().unwrap(),
            start_block_number,
        );

        for (idx, block) in epoch_blocks.iter().enumerate() {
            if idx > 0 {
                block_context.next_block(block);
            }

            self.process_block_transactions(
                &block_context,
                state,
                &mut epoch_recorder,
            )?;
        }

        if self.pos_verifier.pos_option().is_some() {
            debug!(
                "put_staking_events: {:?} height={} len={}",
                pivot_block.hash(),
                pivot_block.block_header.height(),
                epoch_recorder.staking_events.len()
            );
            self.pos_verifier
                .consensus_db()
                .put_staking_events(
                    pivot_block.block_header.height(),
                    pivot_block.hash(),
                    epoch_recorder.staking_events,
                )
                .map_err(|e| {
                    cfx_statedb::Error::from(DbErrorKind::PosDatabaseError(
                        format!("{:?}", e),
                    ))
                })?;
        }

        if on_local_pivot {
            self.tx_pool.recycle_transactions(epoch_recorder.repack_tx);
        }

        debug!("Finish processing tx for epoch");
        Ok(epoch_recorder.receipts)
    }

    fn prefetch_storage_for_execution(
        &self, epoch_id: EpochId, state: &mut State,
        epoch_blocks: &Vec<Arc<Block>>,
    ) {
        // Prefetch accounts for transactions.
        // The return value _prefetch_join_handles is used to join all threads
        // before the exit of this function.
        let prefetch_join_handles = match self
            .execution_state_prefetcher
            .as_ref()
        {
            Some(prefetcher) => {
                let mut accounts = vec![];
                for block in epoch_blocks.iter() {
                    for transaction in block.transactions.iter() {
                        accounts.push(&transaction.sender);
                        match transaction.action() {
                            Action::Call(ref address) => accounts.push(address),
                            _ => {}
                        }
                    }
                }

                prefetch_accounts(prefetcher, epoch_id, state, accounts)
            }
            None => PrefetchTaskHandle {
                task_epoch_id: epoch_id,
                state,
                prefetcher: None,
                accounts: vec![],
            },
        };

        // TODO:
        //   Make the state shared ref for vm execution, then remove this drop.
        //   When the state can be made shared, prefetch can happen at the same
        //   time of the execution, the vm execution do not have to wait
        //   for prefetching to finish.
        prefetch_join_handles.wait_for_task();
        drop(prefetch_join_handles);
    }

    fn make_block_env(&self, block_context: &BlockProcessContext) -> Env {
        let BlockProcessContext {
            epoch_context:
                &EpochProcessContext {
                    pivot_block,
                    base_gas_price,
                    burnt_gas_price,
                    ..
                },
            block,
            block_number,
            last_hash,
        } = *block_context;

        let last_block_header = &self.data_man.block_header_by_hash(&last_hash);

        let pos_id = last_block_header
            .as_ref()
            .and_then(|header| header.pos_reference().as_ref());
        let pos_view_number =
            pos_id.and_then(|id| self.pos_verifier.get_pos_view(id));
        let pivot_decision_epoch = pos_id
            .and_then(|id| self.pos_verifier.get_pivot_decision(id))
            .and_then(|hash| self.data_man.block_header_by_hash(&hash))
            .map(|header| header.height());

        let epoch_height = pivot_block.block_header.height();
        let chain_id = self.machine.params().chain_id_map(epoch_height);
        Env {
            chain_id,
            number: block_number,
            author: block.block_header.author().clone(),
            timestamp: pivot_block.block_header.timestamp(),
            difficulty: block.block_header.difficulty().clone(),
            accumulated_gas_used: U256::zero(),
            last_hash,
            gas_limit: U256::from(block.block_header.gas_limit()),
            epoch_height,
            pos_view: pos_view_number,
            finalized_epoch: pivot_decision_epoch,
            transaction_epoch_bound: self
                .verification_config
                .transaction_epoch_bound,
            base_gas_price,
            burnt_gas_price,
        }
    }

    fn process_block_transactions(
        &self, block_context: &BlockProcessContext, state: &mut State,
        epoch_recorder: &mut EpochProcessRecorder,
    ) -> DbResult<()> {
        let BlockProcessContext {
            epoch_context: &EpochProcessContext { on_local_pivot, .. },
            block,
            block_number,
            ..
        } = *block_context;

        debug!(
            "process txs in block: hash={:?}, tx count={:?}",
            block.hash(),
            block.transactions.len()
        );

        // TODO: ideally, this function should not have return value.
        // However, the previous implementation read `secondary_reward` in an
        // intermediate step. Since we are not sure which steps will influnce
        // `secondary_reward`, we must `secondary_reward` at the same point to
        // keep the backward compatible.
        let secondary_reward =
            self.before_block_execution(state, block_number, block)?;

        let mut env = self.make_block_env(block_context);

        let mut block_recorder =
            BlockProcessRecorder::new(epoch_recorder.evm_tx_idx);

        for (idx, transaction) in block.transactions.iter().enumerate() {
            self.process_transaction(
                idx,
                transaction,
                block_context,
                state,
                &mut env,
                on_local_pivot,
                &mut block_recorder,
            )?;
        }

        block_recorder.finish_block(
            &self.data_man,
            epoch_recorder,
            block_context,
            secondary_reward,
        );

        Ok(())
    }

    fn process_transaction(
        &self, idx: usize, transaction: &Arc<SignedTransaction>,
        block_context: &BlockProcessContext, state: &mut State, env: &mut Env,
        on_local_pivot: bool, recorder: &mut BlockProcessRecorder,
    ) -> DbResult<()> {
        let rpc_index = recorder.tx_idx[transaction.space()];

        let block = &block_context.block;

        let machine = self.machine.as_ref();

        let spec = machine.spec(env.number, env.epoch_height);
        let observer = if self.config.executive_trace {
            Observer::with_tracing()
        } else {
            Observer::with_no_tracing()
        };

        let options = TransactOptions {
            observer,
            settings: TransactSettings::all_checks(),
        };

        let execution_outcome =
            ExecutiveContext::new(state, env, machine, &spec)
                .transact(transaction, options)?;
        execution_outcome.log(transaction, &block_context.block.hash());

        if let Some(burnt_fee) = execution_outcome
            .try_as_executed()
            .and_then(|e| e.burnt_fee)
        {
            state.burn_by_cip1559(burnt_fee);
        };

        let r = make_process_tx_outcome(
            execution_outcome,
            &mut env.accumulated_gas_used,
            transaction.hash,
            &spec,
        );

        if r.receipt.tx_success() {
            GOOD_TPS_METER.mark(1);
        }

        let tx_skipped = r.receipt.tx_skipped();
        let phantom_txs = r.phantom_txs.clone();

        recorder.receive_tx_outcome(r, transaction, block_context);

        if !on_local_pivot || tx_skipped {
            return Ok(());
        }

        let hash = transaction.hash();

        self.data_man.insert_transaction_index(
            &hash,
            &TransactionIndex {
                block_hash: block.hash(),
                real_index: idx,
                is_phantom: false,
                rpc_index: Some(rpc_index),
            },
        );

        // persist tx index for phantom transactions.
        // note: in some cases, pivot chain reorgs will result in
        // different phantom txs (with different hashes) for the
        // same Conflux space tx. we do not remove invalidated
        // hashes here, but leave it up to the RPC layer to handle
        // this instead.
        let evm_chain_id = env.chain_id[&Space::Ethereum];
        let evm_tx_index = &mut recorder.tx_idx[Space::Ethereum];

        for ptx in phantom_txs {
            self.data_man.insert_transaction_index(
                &ptx.into_eip155(evm_chain_id).hash(),
                &TransactionIndex {
                    block_hash: block.hash(),
                    real_index: idx,
                    is_phantom: true,
                    rpc_index: Some(*evm_tx_index),
                },
            );

            *evm_tx_index += 1;
        }

        Ok(())
    }

    fn before_epoch_execution(
        &self, state: &mut State, pivot_block: &Block,
    ) -> DbResult<()> {
        let params = self.machine.params();

        let epoch_number = pivot_block.block_header.height();
        let hash = pivot_block.hash();

        if epoch_number >= params.transition_heights.cip133e {
            state.set_system_storage(
                epoch_hash_slot(epoch_number).into(),
                U256::from_big_endian(&hash.0),
            )?;
        }
        Ok(())
    }

    pub fn before_block_execution(
        &self, state: &mut State, block_number: BlockNumber, block: &Block,
    ) -> DbResult<U256> {
        let params = self.machine.params();
        let transition_numbers = &params.transition_numbers;

        let cip94_start = transition_numbers.cip94n;
        let period = params.params_dao_vote_period;
        // Update/initialize parameters before processing rewards.
        if block_number >= cip94_start
            && (block_number - cip94_start) % period == 0
        {
            let set_pos_staking = block_number > transition_numbers.cip105;
            initialize_or_update_dao_voted_params(state, set_pos_staking)?;
        }

        // Initialize old_storage_point_prop_ratio in the state.
        // The time may not be in the vote period boundary, so this is not
        // integrated with `initialize_or_update_dao_voted_params`, but
        // that function will update the value after cip107 is enabled
        // here.
        if block_number == transition_numbers.cip107 {
            initialize_cip107(state)?;
        }

        if block_number >= transition_numbers.cip133b {
            state.set_system_storage(
                block_hash_slot(block_number).into(),
                U256::from_big_endian(&block.hash().0),
            )?;
        }

        if block_number == transition_numbers.cip137 {
            initialize_cip137(state);
        }

        if block_number < transition_numbers.cip43a {
            state.bump_block_number_accumulate_interest();
        }

        let secondary_reward = state.secondary_reward();

        state.inc_distributable_pos_interest(block_number)?;

        initialize_internal_contract_accounts(
            state,
            self.machine
                .internal_contracts()
                .initialized_at(block_number),
        )?;

        Ok(secondary_reward)
    }
}

struct EpochProcessContext<'a> {
    on_local_pivot: bool,
    executive_trace: bool,

    pivot_block: &'a Block,

    base_gas_price: U256,
    burnt_gas_price: U256,
}

struct BlockProcessContext<'a, 'b> {
    epoch_context: &'b EpochProcessContext<'a>,
    block: &'b Block,
    block_number: u64,
    last_hash: H256,
}

impl<'a, 'b> BlockProcessContext<'a, 'b> {
    fn first_block(
        epoch_context: &'b EpochProcessContext<'a>, block: &'b Block,
        start_block_number: u64,
    ) -> Self {
        let EpochProcessContext { pivot_block, .. } = *epoch_context;
        let last_hash = *pivot_block.block_header.parent_hash();
        Self {
            epoch_context,
            block,
            block_number: start_block_number,
            last_hash,
        }
    }

    fn next_block(&mut self, block: &'b Block) {
        self.last_hash = self.block.hash();
        self.block_number += 1;
        self.block = block;
    }
}

#[derive(Default)]
struct EpochProcessRecorder {
    receipts: Vec<Arc<BlockReceipts>>,
    staking_events: Vec<StakingEvent>,
    repack_tx: Vec<Arc<SignedTransaction>>,

    evm_tx_idx: usize,
}

impl EpochProcessRecorder {
    fn new() -> Self { Default::default() }
}

struct BlockProcessRecorder {
    receipt: Vec<Receipt>,
    tx_error_msg: Vec<String>,
    traces: Vec<TransactionExecTraces>,
    repack_tx: Vec<Arc<SignedTransaction>>,
    staking_events: Vec<StakingEvent>,

    tx_idx: SpaceMap<usize>,
}

impl BlockProcessRecorder {
    fn new(evm_tx_idx: usize) -> BlockProcessRecorder {
        let mut tx_idx = SpaceMap::default();
        tx_idx[Space::Ethereum] = evm_tx_idx;
        Self {
            receipt: vec![],
            tx_error_msg: vec![],
            traces: vec![],
            repack_tx: vec![],
            staking_events: vec![],
            tx_idx,
        }
    }

    fn receive_tx_outcome(
        &mut self, r: ProcessTxOutcome, tx: &Arc<SignedTransaction>,
        block_context: &BlockProcessContext,
    ) {
        let EpochProcessContext {
            on_local_pivot,
            executive_trace,
            ..
        } = *block_context.epoch_context;

        if on_local_pivot && r.consider_repacked {
            self.repack_tx.push(tx.clone())
        }

        let not_skipped = !r.receipt.tx_skipped();

        if executive_trace {
            self.traces.push(r.tx_traces.into());
        }

        self.receipt.push(r.receipt);
        self.tx_error_msg.push(r.tx_exec_error_msg);
        self.staking_events.extend(r.tx_staking_events);

        match tx.space() {
            Space::Native => {
                self.tx_idx[Space::Native] += 1;
            }
            Space::Ethereum if not_skipped => {
                self.tx_idx[Space::Ethereum] += 1;
            }
            _ => {}
        };
    }

    fn finish_block(
        self, data_man: &BlockDataManager,
        epoch_recorder: &mut EpochProcessRecorder,
        block_context: &BlockProcessContext, secondary_reward: U256,
    ) {
        let BlockProcessContext {
            epoch_context:
                &EpochProcessContext {
                    on_local_pivot,
                    executive_trace,
                    pivot_block,
                    ..
                },
            block,
            block_number,
            ..
        } = *block_context;

        let block_receipts = Arc::new(BlockReceipts {
            receipts: self.receipt,
            // An existing bug makes the block_number is one larger than the
            // actual.
            block_number: block_number + 1,
            secondary_reward,
            tx_execution_error_messages: self.tx_error_msg,
        });

        epoch_recorder.receipts.push(block_receipts.clone());
        epoch_recorder.staking_events.extend(self.staking_events);
        epoch_recorder.repack_tx.extend(self.repack_tx);
        epoch_recorder.evm_tx_idx = self.tx_idx[Space::Ethereum];

        if executive_trace {
            data_man.insert_block_traces(
                block.hash(),
                self.traces.into(),
                pivot_block.hash(),
                on_local_pivot,
            );
        }

        data_man.insert_block_execution_result(
            block.hash(),
            pivot_block.hash(),
            block_receipts.clone(),
            on_local_pivot,
        );
    }
}
