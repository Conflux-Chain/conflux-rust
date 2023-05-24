// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait StateTrait: CheckpointTrait + AsStateOpsTrait {
    type Substate;
    type Spec;

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
        &mut self, substate: &Self::Substate, tracer: &mut dyn StateTracer,
        spec: &Self::Spec, dry_run_no_charge: bool,
    ) -> DbResult<CollateralCheckResult>;

    // FIXME: add doc string.
    fn collect_and_settle_collateral(
        &mut self, original_sender: &Address, storage_limit: &U256,
        substate: &mut Self::Substate, tracer: &mut dyn StateTracer,
        spec: &Self::Spec, dry_run_no_charge: bool,
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
    fn bump_block_number_accumulate_interest(&mut self);

    fn secondary_reward(&self) -> U256;

    fn pow_base_reward(&self) -> U256;

    /// Maintain `total_issued_tokens`.s
    fn add_total_issued(&mut self, v: U256);

    /// Maintain `total_issued_tokens`. This is only used in the extremely
    /// unlikely case that there are a lot of partial invalid blocks.
    fn subtract_total_issued(&mut self, v: U256);

    fn add_total_pos_staking(&mut self, v: U256);

    fn add_total_evm_tokens(&mut self, v: U256);

    fn subtract_total_evm_tokens(&mut self, v: U256);

    fn inc_distributable_pos_interest(
        &mut self, current_block_number: u64,
    ) -> DbResult<()>;

    fn distribute_pos_interest<'a>(
        &mut self, pos_points: Box<dyn Iterator<Item = (&'a H256, u64)> + 'a>,
        account_start_nonce: U256, current_block_number: u64,
    ) -> DbResult<Vec<(Address, H256, U256)>>;

    fn new_contract_with_admin(
        &mut self, contract: &AddressWithSpace, admin: &Address, balance: U256,
        nonce: U256, storage_layout: Option<StorageLayout>, cip107: bool,
    ) -> DbResult<()>;

    fn balance(&self, address: &AddressWithSpace) -> DbResult<U256>;

    fn is_contract_with_code(
        &self, address: &AddressWithSpace,
    ) -> DbResult<bool>;

    fn sponsor_for_gas(&self, address: &Address) -> DbResult<Option<Address>>;

    fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Option<Address>>;

    fn set_sponsor_for_gas(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    ) -> DbResult<()>;

    fn set_sponsor_for_collateral(
        &mut self, address: &Address, sponsor: &Address,
        sponsor_balance: &U256, is_cip107: bool,
    ) -> DbResult<U256>;

    fn sponsor_info(&self, address: &Address) -> DbResult<Option<SponsorInfo>>;

    fn sponsor_gas_bound(&self, address: &Address) -> DbResult<U256>;

    fn sponsor_balance_for_gas(&self, address: &Address) -> DbResult<U256>;

    fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256>;

    fn avaliable_storage_point_for_collateral(
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

    fn nonce(&self, address: &AddressWithSpace) -> DbResult<U256>;

    fn init_code(
        &mut self, address: &AddressWithSpace, code: Vec<u8>, owner: Address,
    ) -> DbResult<()>;

    fn code_hash(&self, address: &AddressWithSpace) -> DbResult<Option<H256>>;

    fn code_size(&self, address: &AddressWithSpace) -> DbResult<Option<usize>>;

    fn code_owner(
        &self, address: &AddressWithSpace,
    ) -> DbResult<Option<Address>>;

    fn code(
        &self, address: &AddressWithSpace,
    ) -> DbResult<Option<Arc<Vec<u8>>>>;

    fn staking_balance(&self, address: &Address) -> DbResult<U256>;

    fn collateral_for_storage(&self, address: &Address) -> DbResult<U256>;

    fn token_collateral_for_storage(&self, address: &Address)
        -> DbResult<U256>;

    fn admin(&self, address: &Address) -> DbResult<Address>;

    fn withdrawable_staking_balance(
        &self, address: &Address, current_block_number: u64,
    ) -> DbResult<U256>;

    fn locked_staking_balance_at_block_number(
        &self, address: &Address, block_number: u64,
    ) -> DbResult<U256>;

    fn deposit_list_length(&self, address: &Address) -> DbResult<usize>;

    fn vote_stake_list_length(&self, address: &Address) -> DbResult<usize>;

    fn genesis_special_clean_account(
        &mut self, address: &Address,
    ) -> DbResult<()>;

    fn clean_account(&mut self, address: &AddressWithSpace) -> DbResult<()>;

    fn inc_nonce(
        &mut self, address: &AddressWithSpace, account_start_nonce: &U256,
    ) -> DbResult<()>;

    fn set_nonce(
        &mut self, address: &AddressWithSpace, nonce: &U256,
    ) -> DbResult<()>;

    fn sub_balance(
        &mut self, address: &AddressWithSpace, by: &U256,
        cleanup_mode: &mut CleanupMode,
    ) -> DbResult<()>;

    fn add_balance(
        &mut self, address: &AddressWithSpace, by: &U256,
        cleanup_mode: CleanupMode, account_start_nonce: U256,
    ) -> DbResult<()>;
    fn add_pos_interest(
        &mut self, address: &Address, by: &U256, cleanup_mode: CleanupMode,
        account_start_nonce: U256,
    ) -> DbResult<()>;
    fn transfer_balance(
        &mut self, from: &AddressWithSpace, to: &AddressWithSpace, by: &U256,
        cleanup_mode: CleanupMode, account_start_nonce: U256,
    ) -> DbResult<()>;

    fn deposit(
        &mut self, address: &Address, amount: &U256, current_block_number: u64,
        cip_97: bool,
    ) -> DbResult<()>;

    fn withdraw(
        &mut self, address: &Address, amount: &U256, cip_97: bool,
    ) -> DbResult<U256>;

    fn vote_lock(
        &mut self, address: &Address, amount: &U256, unlock_block_number: u64,
    ) -> DbResult<()>;

    fn remove_expired_vote_stake_info(
        &mut self, address: &Address, current_block_number: u64,
    ) -> DbResult<()>;

    fn total_issued_tokens(&self) -> U256;

    fn total_staking_tokens(&self) -> U256;

    fn total_storage_tokens(&self) -> U256;

    fn total_espace_tokens(&self) -> U256;

    fn used_storage_points(&self) -> U256;

    fn converted_storage_points(&self) -> U256;

    fn total_pos_staking_tokens(&self) -> U256;

    fn distributable_pos_interest(&self) -> U256;

    fn last_distribute_block(&self) -> u64;

    fn remove_contract(&mut self, address: &AddressWithSpace) -> DbResult<()>;

    fn exists(&self, address: &AddressWithSpace) -> DbResult<bool>;

    fn exists_and_not_null(&self, address: &AddressWithSpace)
        -> DbResult<bool>;

    fn storage_at(
        &self, address: &AddressWithSpace, key: &[u8],
    ) -> DbResult<U256>;

    fn set_storage(
        &mut self, address: &AddressWithSpace, key: Vec<u8>, value: U256,
        owner: Address,
    ) -> DbResult<()>;

    fn update_pos_status(
        &mut self, identifier: H256, number: u64,
    ) -> DbResult<()>;

    fn pos_locked_staking(&self, address: &Address) -> DbResult<U256>;

    fn read_vote(&self, address: &Address) -> DbResult<Vec<u8>>;

    fn set_system_storage(&mut self, key: Vec<u8>, value: U256)
        -> DbResult<()>;

    fn get_system_storage(&self, key: &[u8]) -> DbResult<U256>;

    fn get_system_storage_opt(&self, key: &[u8]) -> DbResult<Option<U256>>;
}

pub trait AsStateOpsTrait: StateOpsTrait {
    fn as_state_ops(&self) -> &dyn StateOpsTrait;
    fn as_mut_state_ops(&mut self) -> &mut dyn StateOpsTrait;
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
use crate::tracer::StateTracer;
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressWithSpace, H256, U256};
use primitives::{EpochId, SponsorInfo, StorageLayout};
use std::sync::Arc;
