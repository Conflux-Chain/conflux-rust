use crate::{
    decode::decode_packet,
    packet::{BlockInput, PacketInput, FLAG_PIVOT, FLAG_SKIPPED_EXECUTION},
};
use anyhow::{anyhow, ensure, Context, Result};
use cfx_config::Configuration;
use cfx_execute_helper::{
    observer::Observer, tx_outcome::make_process_tx_outcome,
};
use cfx_executor::{
    executive::{ExecutiveContext, TransactOptions, TransactSettings},
    internal_contract::{
        block_hash_slot, epoch_hash_slot, initialize_internal_contract_accounts,
    },
    machine::{Machine, VmFactory},
    state::{initialize_cip107, initialize_cip137, State},
};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    consensus_internal::REWARD_EPOCH_COUNT, genesis::GENESIS_ACCOUNT_ADDRESS,
};
use cfx_statedb::StateDb;
use cfx_storage::{StateIndex, StorageManager, StorageManagerTrait};
use cfx_types::{Address, AddressSpaceUtil, SpaceMap, H256, U256};
use cfx_vm_types::Env;
use cfxcore::{
    genesis_block::{self, genesis_block},
    verification::compute_receipts_root,
    NodeType,
};
use clap::{Arg, ArgAction, Command};
use primitives::{receipt::BlockReceipts, BlockHeaderBuilder};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    sync::Arc,
};
use tempfile::TempDir;

#[derive(Debug, Clone)]
pub struct ReplayExecConfig {
    pub config_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ReplayExecReport {
    pub epoch_count: usize,
    pub block_count: usize,
    pub transaction_count: usize,
    pub receipts_root_prefix_matches: usize,
    pub logs_bloom_prefix_matches: usize,
    pub state_root_prefix_matches: usize,
    pub epochs: Vec<EpochExecReport>,
}

#[derive(Debug, Clone)]
pub struct EpochExecReport {
    pub pivot_height: u64,
    pub deferred_height: u64,
    pub pivot_hash: H256,
    pub block_count: usize,
    pub transaction_count: usize,
    pub computed_state_root: H256,
    pub expected_state_root_prefix: [u8; 4],
    pub state_root_prefix_match: bool,
    pub computed_receipts_root: H256,
    pub expected_receipts_root_prefix: [u8; 4],
    pub receipts_root_prefix_match: bool,
    pub computed_logs_bloom_hash: H256,
    pub expected_logs_bloom_hash_prefix: [u8; 4],
    pub logs_bloom_prefix_match: bool,
}

pub struct ReplayExecutor {
    conf: Configuration,
    _temp_dir: Option<TempDir>,
    // Still used to build genesis under both backends; under the minimal-mpt
    // backend it is not consulted again after construction.
    #[cfg_attr(feature = "backend-minimal-mpt", allow(dead_code))]
    storage_manager: Arc<StorageManager>,
    machine: Arc<Machine>,
    #[cfg_attr(feature = "backend-minimal-mpt", allow(dead_code))]
    snapshot_epoch_count: u32,
    previous_epoch_hash: H256,
    previous_state_root: StateRootWithAuxInfo,
    commitments_by_height: BTreeMap<u64, EpochCommitment>,
    executed_epochs_by_height: BTreeMap<u64, ExecutedEpochData>,
    // Under the minimal-mpt backend, the single latest state shared across
    // epochs, seeded from the genesis dump. The cfx-storage `storage_manager`
    // above is still used to build genesis; only the per-epoch execution state
    // comes from here instead.
    #[cfg(feature = "backend-minimal-mpt")]
    minimal_backend: crate::minimal_backend::MinimalBackend,
}

impl ReplayExecutor {
    pub fn new(config: ReplayExecConfig) -> Result<Self> {
        let config_path = config
            .config_path
            .to_str()
            .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?;
        let mut conf = parse_configuration(config_path)
            .map_err(|e| anyhow!("load config: {e}"))?;

        let temp_dir =
            tempfile::tempdir().context("create replay temp state dir")?;
        conf.raw_conf.conflux_data_dir =
            temp_dir.path().to_string_lossy().into_owned();

        let vm = VmFactory::new(1024 * 32);
        let machine =
            Arc::new(Machine::new_with_builtin(conf.common_params(), vm));
        let storage_manager = Arc::new(
            StorageManager::new(conf.storage_config(&NodeType::Archive))
                .context("initialize replay storage manager")?,
        );

        let genesis_accounts =
            genesis_block::default(conf.is_test_or_dev_mode());
        let genesis = genesis_block(
            &storage_manager,
            genesis_accounts,
            GENESIS_ACCOUNT_ADDRESS,
            U256::zero(),
            machine.clone(),
            conf.raw_conf.execute_genesis,
            conf.raw_conf.chain_id,
            &None,
        );
        storage_manager.notify_genesis_hash(genesis.hash());
        let previous_epoch_hash = genesis.hash();
        let genesis_commitment = EpochCommitment {
            state_root: *genesis.block_header.deferred_state_root(),
            receipts_root: *genesis.block_header.deferred_receipts_root(),
            logs_bloom_hash: *genesis.block_header.deferred_logs_bloom_hash(),
        };
        let mut genesis_state = storage_manager
            .get_state_no_commit(
                StateIndex::new_for_readonly(
                    &previous_epoch_hash,
                    &StateRootWithAuxInfo::genesis(&previous_epoch_hash),
                ),
                false,
                None,
            )
            .context("open genesis state")?
            .ok_or_else(|| anyhow!("genesis state missing"))?;
        let previous_state_root = genesis_state
            .get_state_root()
            .context("read genesis state root")?;
        // Seed the minimal-mpt backend with the genesis state. The whole
        // genesis lives in the delta trie at this point, so reading with an
        // empty address prefix dumps every genesis key/value (both spaces) in
        // canonical form. They are loaded into the delta uncommitted (height
        // stays 0), matching where the real backend keeps genesis until the
        // first snapshot boundary.
        #[cfg(feature = "backend-minimal-mpt")]
        let minimal_backend = {
            let genesis_kvs = genesis_state
                .read_all(
                    primitives::StorageKey::AddressPrefixKey(b"")
                        .with_native_space(),
                )
                .map_err(|e| anyhow!("dump genesis state: {e}"))?
                .unwrap_or_default();
            crate::minimal_backend::MinimalBackend::from_genesis_kvs(
                genesis_kvs,
            )
            .map_err(|e| anyhow!("seed minimal backend genesis: {e}"))?
        };
        let snapshot_epoch_count = conf
            .storage_config(&NodeType::Archive)
            .consensus_param
            .snapshot_epoch_count;

        Ok(Self {
            conf,
            _temp_dir: Some(temp_dir),
            storage_manager,
            machine,
            snapshot_epoch_count,
            previous_epoch_hash,
            previous_state_root,
            commitments_by_height: BTreeMap::from([(0, genesis_commitment)]),
            executed_epochs_by_height: BTreeMap::new(),
            #[cfg(feature = "backend-minimal-mpt")]
            minimal_backend,
        })
    }

    pub fn execute_packet(
        &mut self, packet: &[u8],
    ) -> Result<ReplayExecReport> {
        let input = decode_packet(packet)?;
        self.execute_input(&input)
    }

    pub fn execute_input(
        &mut self, input: &PacketInput,
    ) -> Result<ReplayExecReport> {
        ensure!(!input.blocks.is_empty(), "packet has no blocks");
        // Strip the epoch skipped-set blocks once, here at the input boundary.
        // Consensus never executes, numbers, rewards, or receipts them — they
        // are carried in the packet only for transaction recycling — so the rest
        // of the executor only ever sees the executed set and never has to
        // re-check the skipped flag.
        let blocks: Vec<&BlockInput> = input
            .blocks
            .iter()
            .filter(|block| block.flags & FLAG_SKIPPED_EXECUTION == 0)
            .collect();
        ensure!(!blocks.is_empty(), "packet has no executed blocks");
        let mut epochs = Vec::new();
        let mut start = 0usize;
        let mut next_block_number = input.first_block_number;
        while start < blocks.len() {
            let Some(relative_pivot) = blocks[start..]
                .iter()
                .position(|block| block.flags & FLAG_PIVOT != 0)
            else {
                anyhow::bail!("epoch group has no pivot block");
            };
            let end = start + relative_pivot;
            let epoch_blocks = &blocks[start..=end];
            epochs.push(self.execute_epoch(epoch_blocks, next_block_number)?);
            next_block_number += epoch_blocks.len() as u64;
            start = end + 1;
        }

        let block_count = blocks.len();
        let transaction_count = blocks
            .iter()
            .map(|block| block.transactions.len())
            .sum();
        Ok(ReplayExecReport {
            epoch_count: epochs.len(),
            block_count,
            transaction_count,
            receipts_root_prefix_matches: epochs
                .iter()
                .filter(|epoch| epoch.receipts_root_prefix_match)
                .count(),
            logs_bloom_prefix_matches: epochs
                .iter()
                .filter(|epoch| epoch.logs_bloom_prefix_match)
                .count(),
            state_root_prefix_matches: epochs
                .iter()
                .filter(|epoch| epoch.state_root_prefix_match)
                .count(),
            epochs,
        })
    }

    fn execute_epoch(
        &mut self, blocks: &[&BlockInput], start_block_number: u64,
    ) -> Result<EpochExecReport> {
        // `blocks` is the epoch's executed set only (skipped-set blocks were
        // stripped at the input boundary), so every block here is executed,
        // numbered, and contributes to the deferred receipts root.
        let pivot = *blocks.last().expect("non-empty epoch");
        let pivot_hash = pivot.hash;
        let mut state = self.open_next_state(pivot)?;
        self.before_epoch_execution(&mut state, pivot)?;

        let mut receipts = Vec::with_capacity(blocks.len());
        let mut block_number = start_block_number;
        let mut last_hash = self.previous_epoch_hash;
        for &block in blocks {
            let block_receipts = self.execute_block(
                block,
                pivot,
                block_number,
                last_hash,
                &mut state,
            )?;
            receipts.push(Arc::new(block_receipts));
            last_hash = block.hash;
            block_number += 1;
        }

        let computed_receipts_root = compute_receipts_root(&receipts);
        let computed_logs_bloom_hash =
            BlockHeaderBuilder::compute_block_logs_bloom_hash(&receipts);
        let end_block_number = block_number.saturating_sub(1);
        if let Some(reward_height) = reward_commitment_height(pivot.height) {
            let reward_epoch = self
                .executed_epochs_by_height
                .get(&reward_height)
                .ok_or_else(|| {
                    anyhow!(
                        "missing reward execution data for height {}",
                        reward_height
                    )
                })?;
            self.process_rewards_and_fees(
                &mut state,
                &reward_epoch.blocks,
                &reward_epoch.receipts,
                end_block_number,
                pivot,
            )?;
        }

        let state_root = state
            .commit(pivot_hash, None)
            .context("commit replay epoch state")?
            .state_root;
        let computed_state_root = state_root.aux_info.state_root_hash;
        self.previous_epoch_hash = pivot_hash;
        self.previous_state_root = state_root;

        let current_commitment = EpochCommitment {
            state_root: computed_state_root,
            receipts_root: computed_receipts_root,
            logs_bloom_hash: computed_logs_bloom_hash,
        };
        let deferred_height = deferred_commitment_height(pivot.height);
        let deferred_commitment = self
            .commitments_by_height
            .get(&deferred_height)
            .ok_or_else(|| {
                anyhow!(
                    "missing deferred execution commitment for height {} \
                     (pivot.height={}, pivot.epoch={})",
                    deferred_height,
                    pivot.height,
                    pivot.epoch,
                )
            })?;
        let expected_state_root_prefix = prefix4(pivot.deferred_state_root);
        let expected_receipts_root_prefix =
            prefix4(pivot.deferred_receipts_root);
        let expected_logs_bloom_hash_prefix =
            prefix4(pivot.deferred_logs_bloom_hash);
        let state_root_prefix_match = prefix4(deferred_commitment.state_root)
            == expected_state_root_prefix;
        let receipts_root_prefix_match =
            prefix4(deferred_commitment.receipts_root)
                == expected_receipts_root_prefix;
        let logs_bloom_prefix_match =
            prefix4(deferred_commitment.logs_bloom_hash)
                == expected_logs_bloom_hash_prefix;
        self.commitments_by_height
            .insert(pivot.height, current_commitment);
        self.executed_epochs_by_height.insert(
            pivot.height,
            ExecutedEpochData {
                blocks: blocks.iter().map(|b| (*b).clone()).collect(),
                receipts: receipts.clone(),
            },
        );
        // Bound memory: a commitment is only re-read DEFERRED_STATE_EPOCH_COUNT
        // epochs later and an executed epoch only REWARD_EPOCH_COUNT epochs
        // later, so older entries are dead. Without this the maps grow with the
        // chain length and a full-chain replay exhausts memory.
        let commitment_floor =
            pivot.height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT + 1);
        self.commitments_by_height =
            self.commitments_by_height.split_off(&commitment_floor);
        let reward_floor =
            pivot.height.saturating_sub(REWARD_EPOCH_COUNT + 1);
        self.executed_epochs_by_height =
            self.executed_epochs_by_height.split_off(&reward_floor);
        Ok(EpochExecReport {
            pivot_height: pivot.height,
            deferred_height,
            pivot_hash,
            block_count: blocks.len(),
            transaction_count: blocks
                .iter()
                .map(|b| b.transactions.len())
                .sum(),
            computed_state_root,
            expected_state_root_prefix,
            state_root_prefix_match,
            computed_receipts_root,
            expected_receipts_root_prefix,
            receipts_root_prefix_match,
            computed_logs_bloom_hash,
            expected_logs_bloom_hash_prefix,
            logs_bloom_prefix_match,
        })
    }

    fn open_next_state(&self, pivot: &BlockInput) -> Result<State> {
        // The minimal-mpt backend keeps only the latest state and is advanced
        // in place each epoch, so there is no `StateIndex` history to consult —
        // every epoch just wraps a fresh adapter over the same shared state.
        #[cfg(feature = "backend-minimal-mpt")]
        {
            let _ = pivot;
            return State::new(StateDb::new(Box::new(
                self.minimal_backend.open(),
            )))
            .context("create replay execution state (minimal-mpt)");
        }
        #[cfg(not(feature = "backend-minimal-mpt"))]
        {
            let state_index = StateIndex::new_for_next_epoch(
                &self.previous_epoch_hash,
                &self.previous_state_root,
                pivot.epoch.saturating_sub(1),
                self.snapshot_epoch_count,
            );
            let storage = self
                .storage_manager
                .get_state_for_next_epoch(state_index, false)
                .context("open replay state for next epoch")?
                .ok_or_else(|| anyhow!("replay state for next epoch missing"))?;
            State::new(StateDb::new(storage))
                .context("create replay execution state")
        }
    }

    fn execute_block(
        &self, block: &BlockInput, pivot: &BlockInput, block_number: u64,
        last_hash: H256, state: &mut State,
    ) -> Result<BlockReceipts> {
        let secondary_reward =
            self.before_block_execution(state, block_number, block)?;
        let mut env =
            self.make_env(block, pivot, block_number, last_hash, state);
        let mut accumulated_gas_used = U256::zero();
        let mut block_receipts = Vec::with_capacity(block.transactions.len());
        let mut errors = Vec::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            let spec = self.machine.spec(env.number, env.epoch_height);
            let options = TransactOptions {
                observer: Observer::with_no_tracing(),
                settings: TransactSettings::all_checks(),
            };
            env.transaction_hash = tx.hash();
            let outcome =
                ExecutiveContext::new(state, &env, &self.machine, &spec)
                    .transact(tx, options)
                    .context("execute replay transaction")?;
            state.update_state_post_tx_execution(!spec.cip645.fix_eip1153);
            if let Some(burnt_fee) =
                outcome.try_as_executed().and_then(|e| e.burnt_fee)
            {
                state.burn_by_cip1559(burnt_fee);
            }
            let processed = make_process_tx_outcome(
                outcome,
                &mut accumulated_gas_used,
                tx.hash(),
                &spec,
            );
            block_receipts.push(processed.receipt);
            errors.push(processed.tx_exec_error_msg);
        }
        Ok(BlockReceipts {
            receipts: block_receipts,
            block_number: block_number + 1,
            secondary_reward,
            tx_execution_error_messages: errors,
        })
    }

    fn make_env(
        &self, block: &BlockInput, pivot: &BlockInput, block_number: u64,
        last_hash: H256, state: &mut State,
    ) -> Env {
        let base_gas_price =
            SpaceMap::new(block.base_price_core, block.base_price_espace);
        let burnt_gas_price =
            base_gas_price.map_all(|x| state.burnt_gas_price(x));
        Env {
            chain_id: self.machine.params().chain_id_map(pivot.epoch),
            number: block_number,
            author: block.author,
            timestamp: pivot.timestamp,
            difficulty: block.difficulty,
            accumulated_gas_used: U256::zero(),
            last_hash,
            gas_limit: block.gas_limit,
            epoch_height: pivot.epoch,
            pos_view: None,
            finalized_epoch: finalized_epoch(
                pivot.epoch,
                block.finalized_epoch,
            ),
            transaction_epoch_bound: self.conf.raw_conf.transaction_epoch_bound,
            base_gas_price,
            burnt_gas_price,
            transaction_hash: H256::zero(),
            ..Default::default()
        }
    }

    fn before_epoch_execution(
        &self, state: &mut State, pivot: &BlockInput,
    ) -> Result<()> {
        let params = self.machine.params();
        if pivot.epoch >= params.transition_heights.cip133e {
            state
                .set_system_storage(
                    epoch_hash_slot(pivot.epoch).into(),
                    U256::from_big_endian(pivot.hash.as_bytes()),
                )
                .context("set epoch hash slot")?;
        }
        if pivot.epoch >= params.transition_heights.eip2935 {
            state
                .set_eip2935_storage(pivot.epoch - 1, self.previous_epoch_hash)
                .context("set eip2935 parent hash")?;
        }
        Ok(())
    }

    fn before_block_execution(
        &self, state: &mut State, block_number: u64, block: &BlockInput,
    ) -> Result<U256> {
        let params = self.machine.params();
        let transition_numbers = &params.transition_numbers;

        let cip94_start = transition_numbers.cip94n;
        let period = params.params_dao_vote_period;
        if block_number >= cip94_start
            && (block_number - cip94_start) % period == 0
        {
            let set_pos_staking = block_number > transition_numbers.cip105;
            cfx_executor::state::initialize_or_update_dao_voted_params(
                state,
                set_pos_staking,
            )
            .context("initialize/update DAO voted params")?;
        }

        if block_number == transition_numbers.cip107 {
            initialize_cip107(state).context("initialize cip107")?;
        }

        if block_number >= transition_numbers.cip133b {
            state
                .set_system_storage(
                    block_hash_slot(block_number).into(),
                    U256::from_big_endian(block.hash.as_bytes()),
                )
                .context("set block hash slot")?;
        }

        if block_number == transition_numbers.cip137 {
            initialize_cip137(state);
        }

        if block_number < transition_numbers.cip43a {
            state.bump_block_number_accumulate_interest();
        }

        let secondary_reward = state.secondary_reward();
        state
            .inc_distributable_pos_interest(block_number)
            .context("increase distributable PoS interest")?;
        initialize_internal_contract_accounts(
            state,
            self.machine
                .internal_contracts()
                .initialized_at(block_number),
        )
        .context("initialize internal contract accounts")?;
        state.commit_cache(false);
        Ok(secondary_reward)
    }

    fn process_rewards_and_fees(
        &self, state: &mut State, blocks: &[BlockInput],
        receipts: &[Arc<BlockReceipts>], end_block_number: u64,
        pivot: &BlockInput,
    ) -> Result<()> {
        let spec = self.machine.spec(end_block_number, pivot.height);
        let mut total_base_reward = U256::zero();
        let mut block_base_rewards = Vec::with_capacity(blocks.len());
        for block in blocks {
            let reward = block.base_reward;
            if !reward.is_zero() {
                total_base_reward += reward;
            }
            block_base_rewards.push(reward);
        }

        let mut tx_fee = HashMap::<TxIdentity, TxExecutionInfo>::new();
        let mut secondary_reward = U256::zero();
        for (block, block_receipts) in blocks.iter().zip(receipts.iter()) {
            secondary_reward += block_receipts.secondary_reward;
            ensure!(
                block.transactions.len() == block_receipts.receipts.len(),
                "transaction and receipt count mismatch for block {:?}",
                block.hash
            );
            for (tx_index, receipt) in
                block_receipts.receipts.iter().enumerate()
            {
                let fee =
                    receipt.gas_fee - receipt.burnt_gas_fee.unwrap_or_default();
                let info = tx_fee
                    .entry(transaction_identity(block, tx_index))
                    .or_insert_with(Default::default);
                if !fee.is_zero() && info.fee.is_zero() {
                    info.fee = fee;
                }
                // Consensus only lets a block share an epoch's transaction fees
                // when it is reward-eligible (`no_reward == false`). The packet
                // records each block's post-penalty `base_reward`, so a zero
                // base reward marks a penalized / no-reward block (e.g. a stale
                // block pulled in long after its height, whose anticone penalty
                // wipes out the reward). Such blocks must not be added to a
                // transaction's packing set, otherwise fees are mis-distributed.
                if !block.base_reward.is_zero() {
                    info.packing_blocks.insert(block.hash);
                }
            }
        }

        let mut block_tx_fees = HashMap::<H256, U256>::new();
        let mut burnt_fee = U256::zero();
        for info in tx_fee.values() {
            if info.packing_blocks.is_empty() {
                burnt_fee += info.fee;
                continue;
            }
            let block_count = U256::from(info.packing_blocks.len());
            let quotient = info.fee / block_count;
            let mut remainder = info.fee - block_count * quotient;
            for block_hash in &info.packing_blocks {
                let reward =
                    block_tx_fees.entry(*block_hash).or_insert(U256::zero());
                *reward += quotient;
                if !remainder.is_zero() {
                    *reward += U256::one();
                    remainder -= U256::one();
                }
            }
        }

        let mut merged_rewards = BTreeMap::<Address, U256>::new();
        let mut allocated_secondary_reward = U256::zero();
        for (block, base_reward) in blocks.iter().zip(block_base_rewards) {
            let fee = block_tx_fees
                .get(&block.hash)
                .copied()
                .unwrap_or_else(U256::zero);
            let total_reward =
                if !base_reward.is_zero() && !total_base_reward.is_zero() {
                    let block_secondary_reward =
                        base_reward * secondary_reward / total_base_reward;
                    allocated_secondary_reward += block_secondary_reward;
                    base_reward + fee + block_secondary_reward
                } else {
                    base_reward + fee
                };
            *merged_rewards.entry(block.author).or_insert(U256::zero()) +=
                total_reward;
        }

        for (address, reward) in merged_rewards {
            if spec.is_valid_address(&address) {
                state
                    .add_balance(&address.with_native_space(), &reward)
                    .context("apply block reward")?;
            }
        }

        let new_mint = total_base_reward + allocated_secondary_reward;
        if new_mint >= burnt_fee {
            state.add_total_issued(new_mint - burnt_fee);
        } else {
            state.sub_total_issued(burnt_fee - new_mint);
        }
        Ok(())
    }

    /// Committed height so far (`== last pivot height`, 0 before any epoch).
    /// Lets the driver know where a resumed run picks up.
    #[cfg(feature = "backend-minimal-mpt")]
    pub fn committed_height(&self) -> u64 {
        self.minimal_backend.height()
    }

    /// Capture a resumable checkpoint at the current (boundary) height. The
    /// trie half reuses minimal-mpt's `PersistedState`; the executor windows
    /// (`commitments_by_height`, `executed_epochs_by_height`) and the
    /// `previous_*` cursor are carried alongside. See [`crate::checkpoint`].
    #[cfg(feature = "backend-minimal-mpt")]
    pub fn export_checkpoint(&self) -> crate::checkpoint::ReplayCheckpoint {
        crate::checkpoint::ReplayCheckpoint::build(
            self.minimal_backend.export_persisted(),
            self.previous_epoch_hash,
            &self.previous_state_root,
            &self.commitments_by_height,
            &self.executed_epochs_by_height,
        )
    }

    /// Rebuild an executor positioned exactly at a checkpoint. Genesis and the
    /// machine are reconstructed by `new`, then the minimal-mpt state and the
    /// executor windows are overwritten from the checkpoint, so execution
    /// continues from the checkpoint height as if it had never stopped.
    #[cfg(feature = "backend-minimal-mpt")]
    pub fn restore(
        config: ReplayExecConfig,
        checkpoint: crate::checkpoint::ReplayCheckpoint,
    ) -> Result<Self> {
        let mut executor = Self::new(config)?;
        let (mmpt, prev_hash, prev_root, commitments, executed) =
            checkpoint.into_parts()?;
        executor.minimal_backend =
            crate::minimal_backend::MinimalBackend::from_persisted(mmpt);
        executor.previous_epoch_hash = prev_hash;
        executor.previous_state_root = prev_root;
        executor.commitments_by_height = commitments;
        executor.executed_epochs_by_height = executed;
        Ok(executor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TxIdentity {
    block_index: usize,
    tx_index: usize,
}

#[derive(Default)]
struct TxExecutionInfo {
    fee: U256,
    packing_blocks: BTreeSet<H256>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(crate) struct EpochCommitment {
    pub(crate) state_root: H256,
    pub(crate) receipts_root: H256,
    pub(crate) logs_bloom_hash: H256,
}

#[derive(Debug, Clone)]
pub(crate) struct ExecutedEpochData {
    pub(crate) blocks: Vec<BlockInput>,
    pub(crate) receipts: Vec<Arc<BlockReceipts>>,
}

fn prefix4(hash: H256) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash.as_bytes()[..4]);
    out
}

fn finalized_epoch(epoch: u64, offset: u64) -> Option<u64> {
    if offset == 0 {
        None
    } else {
        Some(epoch.saturating_sub(offset))
    }
}

fn deferred_commitment_height(height: u64) -> u64 {
    if height <= DEFERRED_STATE_EPOCH_COUNT {
        0
    } else {
        height - DEFERRED_STATE_EPOCH_COUNT
    }
}

fn reward_commitment_height(height: u64) -> Option<u64> {
    if height <= REWARD_EPOCH_COUNT {
        None
    } else {
        Some(height - REWARD_EPOCH_COUNT)
    }
}

fn transaction_identity(block: &BlockInput, tx_index: usize) -> TxIdentity {
    let (block_index, tx_index) = block
        .transaction_refs
        .get(tx_index)
        .copied()
        .flatten()
        .unwrap_or((block.index, tx_index));
    TxIdentity {
        block_index,
        tx_index,
    }
}

fn parse_configuration(config_path: &str) -> Result<Configuration, String> {
    let matches = Command::new("cfx-replay-exec-config")
        .arg(Arg::new("config").long("config").num_args(1))
        .arg(
            Arg::new("archive")
                .long("archive")
                .action(ArgAction::SetTrue),
        )
        .arg(Arg::new("full").long("full").action(ArgAction::SetTrue))
        .arg(Arg::new("light").long("light").action(ArgAction::SetTrue))
        .try_get_matches_from([
            "cfx-replay-exec-config",
            "--config",
            config_path,
        ])
        .map_err(|e| e.to_string())?;
    Configuration::parse(&matches)
}
