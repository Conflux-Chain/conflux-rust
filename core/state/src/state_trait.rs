// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait StateTrait: CheckpointTrait {
    type Substate: SubstateTrait;

    /// Collects the cache (`ownership_change` in `OverlayAccount`) of storage
    /// change and write to substate.
    /// It is idempotent. But its execution is costly.
    fn collect_ownership_changed(
        &mut self, substate: &mut Self::Substate,
    ) -> DbResult<()>;

    /// Charge and refund all the storage collaterals.
    /// The suicided addresses are skimmed because their collateral have been
    /// checked out. This function should only be called in post-processing
    /// of a transaction.
    fn settle_collateral_for_all(
        &mut self, substate: &Self::Substate, account_start_nonce: U256,
    ) -> DbResult<CollateralCheckResult>;

    // FIXME: add doc string.
    fn collect_and_settle_collateral(
        &mut self, original_sender: &Address, storage_limit: &U256,
        substate: &mut Self::Substate, account_start_nonce: U256,
    ) -> DbResult<CollateralCheckResult>;

    // TODO: maybe we can find a better interface for doing the suicide
    // post-processing.
    fn record_storage_and_whitelist_entries_release(
        &mut self, address: &Address, substate: &mut Self::Substate,
    ) -> DbResult<()>;

    fn compute_state_root(
        &mut self, debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>;

    fn commit(
        &mut self, epoch_id: EpochId,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>;
}

pub trait StateOpsTrait {
    /// Calculate the secondary reward for the next block number.
    fn bump_block_number_accumulate_interest(&mut self) -> U256;

    /// Maintain `total_issued_tokens`.
    fn add_total_issued(&mut self, v: U256);

    /// Maintain `total_issued_tokens`. This is only used in the extremely
    /// unlikely case that there are a lot of partial invalid blocks.
    fn subtract_total_issued(&mut self, v: U256);

    fn new_contract_with_admin(
        &mut self, contract: &Address, admin: &Address, balance: U256,
        nonce: U256, storage_layout: Option<StorageLayout>,
    ) -> DbResult<()>;

    fn balance(&self, address: &Address) -> DbResult<U256>;

    fn is_contract_with_code(&self, address: &Address) -> DbResult<bool>;

    fn sponsor_for_gas(&self, address: &Address) -> DbResult<Option<Address>>;

    fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Option<Address>>;

    fn set_sponsor_for_gas(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    ) -> DbResult<()>;

    fn set_sponsor_for_collateral(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
    ) -> DbResult<()>;

    fn sponsor_info(&self, address: &Address) -> DbResult<Option<SponsorInfo>>;

    fn sponsor_gas_bound(&self, address: &Address) -> DbResult<U256>;

    fn sponsor_balance_for_gas(&self, address: &Address) -> DbResult<U256>;

    fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256>;

    fn set_admin(
        &mut self, contract_address: &Address, admin: &Address,
    ) -> DbResult<()>;

    fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()>;

    fn add_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()>;

    fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()>;

    fn add_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()>;

    fn check_commission_privilege(
        &self, contract_address: &Address, user: &Address,
    ) -> DbResult<bool>;

    fn add_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>;

    fn remove_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>;

    fn nonce(&self, address: &Address) -> DbResult<U256>;

    fn init_code(
        &mut self, address: &Address, code: Vec<u8>, owner: Address,
    ) -> DbResult<()>;

    fn code_hash(&self, address: &Address) -> DbResult<Option<H256>>;

    fn code_size(&self, address: &Address) -> DbResult<Option<usize>>;

    fn code_owner(&self, address: &Address) -> DbResult<Option<Address>>;

    fn code(&self, address: &Address) -> DbResult<Option<Arc<Vec<u8>>>>;

    fn staking_balance(&self, address: &Address) -> DbResult<U256>;

    fn collateral_for_storage(&self, address: &Address) -> DbResult<U256>;

    fn admin(&self, address: &Address) -> DbResult<Address>;

    fn withdrawable_staking_balance(
        &self, address: &Address, current_block_number: u64,
    ) -> DbResult<U256>;

    fn locked_staking_balance_at_block_number(
        &self, address: &Address, block_number: u64,
    ) -> DbResult<U256>;

    fn deposit_list_length(&self, address: &Address) -> DbResult<usize>;

    fn vote_stake_list_length(&self, address: &Address) -> DbResult<usize>;

    fn clean_account(&mut self, address: &Address) -> DbResult<()>;

    fn inc_nonce(
        &mut self, address: &Address, account_start_nonce: &U256,
    ) -> DbResult<()>;

    fn set_nonce(&mut self, address: &Address, nonce: &U256) -> DbResult<()>;

    fn sub_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: &mut CleanupMode,
    ) -> DbResult<()>;

    fn add_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: CleanupMode,
        account_start_nonce: U256,
    ) -> DbResult<()>;
    fn transfer_balance(
        &mut self, from: &Address, to: &Address, by: &U256,
        cleanup_mode: CleanupMode, account_start_nonce: U256,
    ) -> DbResult<()>;

    fn deposit(
        &mut self, address: &Address, amount: &U256, current_block_number: u64,
    ) -> DbResult<()>;

    fn withdraw(&mut self, address: &Address, amount: &U256) -> DbResult<U256>;

    fn vote_lock(
        &mut self, address: &Address, amount: &U256, unlock_block_number: u64,
    ) -> DbResult<()>;

    fn remove_expired_vote_stake_info(
        &mut self, address: &Address, current_block_number: u64,
    ) -> DbResult<()>;

    fn total_issued_tokens(&self) -> &U256;

    fn total_staking_tokens(&self) -> &U256;

    fn total_storage_tokens(&self) -> &U256;

    fn remove_contract(&mut self, address: &Address) -> DbResult<()>;

    fn exists(&self, address: &Address) -> DbResult<bool>;

    fn exists_and_not_null(&self, address: &Address) -> DbResult<bool>;

    fn storage_at(&self, address: &Address, key: &[u8]) -> DbResult<U256>;

    fn set_storage(
        &mut self, address: &Address, key: Vec<u8>, value: U256, owner: Address,
    ) -> DbResult<()>;
}

pub trait CheckpointTrait: StateOpsTrait {
    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index. The checkpoint records any old value which is alive at the
    /// creation time of the checkpoint and updated after that and before
    /// the creation of the next checkpoint.
    fn checkpoint(&mut self) -> usize;

    /// Merge last checkpoint with previous.
    /// Caller should make sure the function
    /// `collect_ownership_changed()` was called before calling
    /// this function.
    fn discard_checkpoint(&mut self);

    /// Revert to the last checkpoint and discard it.
    fn revert_to_checkpoint(&mut self);
}

use super::{CleanupMode, CollateralCheckResult};
use crate::SubstateTrait;
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, H256, U256};
use primitives::{EpochId, SponsorInfo, StorageLayout};
use std::sync::Arc;
