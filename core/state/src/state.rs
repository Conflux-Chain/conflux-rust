// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct State<StateDbStorage> {
    db: StateDbGeneric<StateDbStorage>,

    // State entries object-cache.
    cache: RwLock<StateObjectCache>,
}

impl<StateDbStorage: StorageStateTrait> StateTrait for State<StateDbStorage> {
    // TODO: wait for SubstateTrait impl.
    type Substate = ();

    fn collect_ownership_changed(
        &mut self, _substate: &mut Self::Substate,
    ) -> Result<()> {
        unimplemented!()
    }

    fn settle_collateral_for_all(
        &mut self, _substate: &Self::Substate,
    ) -> Result<CollateralCheckResult> {
        unimplemented!()
    }

    fn collect_and_settle_collateral(
        &mut self, _original_sender: &Address, _storage_limit: &U256,
        _substate: &mut Self::Substate,
    ) -> Result<CollateralCheckResult>
    {
        unimplemented!()
    }

    fn record_storage_and_whitelist_entries_release(
        &mut self, _address: &Address, _substate: &mut Self::Substate,
    ) -> Result<()> {
        unimplemented!()
    }

    fn compute_state_root(
        &mut self, debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<StateRootWithAuxInfo> {
        self.db.compute_state_root(debug_record)
    }

    fn commit(
        &mut self, epoch_id: EpochId,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<StateRootWithAuxInfo>
    {
        self.db.commit(epoch_id, debug_record)
    }
}

impl<StateDbStorage: StorageStateTrait> CheckpointTrait
    for State<StateDbStorage>
{
    fn checkpoint(&mut self) -> usize { self.db.checkpoint() }

    fn discard_checkpoint(&mut self) { self.db.discard_checkpoint(); }

    fn revert_to_checkpoint(&mut self) {
        // Drop the cache because of the revert.
        self.cache.write().clear();
        self.db.revert_to_checkpoint();
    }
}

impl<StateDbStorage: StorageStateTrait> StateOpsTrait
    for State<StateDbStorage>
{
    fn bump_block_number_accumulate_interest(&mut self) -> U256 {
        unimplemented!()
    }

    fn add_total_issued(&mut self, _v: U256) { unimplemented!() }

    fn subtract_total_issued(&mut self, _v: U256) { unimplemented!() }

    fn new_contract_with_admin(
        &mut self, _contract: &Address, _admin: &Address, _balance: U256,
        _nonce: U256, _storage_layout: Option<StorageLayout>,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn balance(&self, address: &Address) -> Result<U256> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.balance)
            .unwrap_or_default())
    }

    fn is_contract_with_code(&self, _address: &Address) -> Result<bool> {
        unimplemented!()
    }

    fn sponsor_for_gas(&self, address: &Address) -> Result<Option<Address>> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map_or(None, |a| maybe_address(&a.sponsor_info.sponsor_for_gas)))
    }

    fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> Result<Option<Address>> {
        Ok(self.cache.read().get_account(address)?.map_or(None, |a| {
            maybe_address(&a.sponsor_info.sponsor_for_collateral)
        }))
    }

    fn set_sponsor_for_gas(
        &self, _address: &Address, _sponsor: &Address, _sponsor_balance: &U256,
        _upper_bound: &U256,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn set_sponsor_for_collateral(
        &self, _address: &Address, _sponsor: &Address, _sponsor_balance: &U256,
    ) -> Result<()> {
        unimplemented!()
    }

    fn sponsor_info(&self, address: &Address) -> Result<Option<SponsorInfo>> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.sponsor_info.clone()))
    }

    fn sponsor_gas_bound(&self, address: &Address) -> Result<U256> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.sponsor_info.sponsor_gas_bound)
            .unwrap_or_default())
    }

    fn sponsor_balance_for_gas(&self, address: &Address) -> Result<U256> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.sponsor_info.sponsor_balance_for_gas)
            .unwrap_or_default())
    }

    fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> Result<U256> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.sponsor_info.sponsor_balance_for_collateral)
            .unwrap_or_default())
    }

    fn set_admin(
        &mut self, _contract_address: &Address, _admin: &Address,
    ) -> Result<()> {
        unimplemented!()
    }

    fn sub_sponsor_balance_for_gas(
        &mut self, _address: &Address, _by: &U256,
    ) -> Result<()> {
        unimplemented!()
    }

    fn add_sponsor_balance_for_gas(
        &mut self, _address: &Address, _by: &U256,
    ) -> Result<()> {
        unimplemented!()
    }

    fn sub_sponsor_balance_for_collateral(
        &mut self, _address: &Address, _by: &U256,
    ) -> Result<()> {
        unimplemented!()
    }

    fn add_sponsor_balance_for_collateral(
        &mut self, _address: &Address, _by: &U256,
    ) -> Result<()> {
        unimplemented!()
    }

    fn check_commission_privilege(
        &self, _contract_address: &Address, _user: &Address,
    ) -> Result<bool> {
        unimplemented!()
    }

    fn add_commission_privilege(
        &mut self, _contract_address: Address, _contract_owner: Address,
        _user: Address,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn remove_commission_privilege(
        &mut self, _contract_address: Address, _contract_owner: Address,
        _user: Address,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn nonce(&self, address: &Address) -> Result<U256> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.nonce)
            .unwrap_or_default())
    }

    fn init_code(
        &mut self, _address: &Address, _code: Vec<u8>, _owner: Address,
    ) -> Result<()> {
        unimplemented!()
    }

    fn code_hash(&self, address: &Address) -> Result<Option<H256>> {
        Ok(self.cache.read().get_account(address)?.map(|a| a.code_hash))
    }

    fn code_size(&self, _address: &Address) -> Result<Option<usize>> {
        unimplemented!()
    }

    fn code_owner(&self, _address: &Address) -> Result<Option<Address>> {
        unimplemented!()
    }

    fn code(&self, _address: &Address) -> Result<Option<Arc<Vec<u8>>>> {
        unimplemented!()
    }

    fn staking_balance(&self, address: &Address) -> Result<U256> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.staking_balance)
            .unwrap_or_default())
    }

    fn collateral_for_storage(&self, address: &Address) -> Result<U256> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.collateral_for_storage)
            .unwrap_or_default())
    }

    fn admin(&self, address: &Address) -> Result<Address> {
        Ok(self
            .cache
            .read()
            .get_account(address)?
            .map(|a| a.admin)
            .unwrap_or_default())
    }

    fn withdrawable_staking_balance(
        &self, _address: &Address, _current_block_number: u64,
    ) -> Result<U256> {
        unimplemented!()
    }

    fn locked_staking_balance_at_block_number(
        &self, _address: &Address, _block_number: u64,
    ) -> Result<U256> {
        unimplemented!()
    }

    fn deposit_list_length(&self, _address: &Address) -> Result<usize> {
        unimplemented!()
    }

    fn vote_stake_list_length(&self, _address: &Address) -> Result<usize> {
        unimplemented!()
    }

    fn clean_account(&mut self, _address: &Address) -> Result<()> {
        unimplemented!()
    }

    fn inc_nonce(&mut self, _address: &Address) -> Result<()> {
        unimplemented!()
    }

    fn set_nonce(&mut self, _address: &Address, _nonce: &U256) -> Result<()> {
        unimplemented!()
    }

    fn sub_balance(
        &mut self, _address: &Address, _by: &U256,
        _cleanup_mode: &mut CleanupMode,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn add_balance(
        &mut self, _address: &Address, _by: &U256, _cleanup_mode: CleanupMode,
    ) -> Result<()> {
        unimplemented!()
    }

    fn transfer_balance(
        &mut self, _from: &Address, _to: &Address, _by: &U256,
        _cleanup_mode: CleanupMode,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn deposit(
        &mut self, _address: &Address, _amount: &U256,
        _current_block_number: u64,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn withdraw(&mut self, _address: &Address, _amount: &U256) -> Result<U256> {
        unimplemented!()
    }

    fn vote_lock(
        &mut self, _address: &Address, _amount: &U256,
        _unlock_block_number: u64,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn remove_expired_vote_stake_info(
        &mut self, _address: &Address, _current_block_number: u64,
    ) -> Result<()> {
        unimplemented!()
    }

    fn total_issued_tokens(&self) -> &U256 { unimplemented!() }

    fn total_staking_tokens(&self) -> &U256 { unimplemented!() }

    fn total_storage_tokens(&self) -> &U256 { unimplemented!() }

    fn remove_contract(&mut self, _address: &Address) -> Result<()> {
        unimplemented!()
    }

    fn exists(&self, _address: &Address) -> Result<bool> { unimplemented!() }

    fn exists_and_not_null(&self, _address: &Address) -> Result<bool> {
        unimplemented!()
    }

    fn storage_at(&self, _address: &Address, _key: &[u8]) -> Result<U256> {
        unimplemented!()
    }

    fn set_storage(
        &mut self, _address: &Address, _key: Vec<u8>, _value: U256,
        _owner: Address,
    ) -> Result<()>
    {
        unimplemented!()
    }
}

use crate::{
    maybe_address,
    state_object_cache::StateObjectCache,
    state_trait::{CheckpointTrait, StateOpsTrait},
    CleanupMode, CollateralCheckResult, StateTrait,
};
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_statedb::{Result, StateDbCheckpointMethods, StateDbGeneric};
use cfx_storage::StorageStateTrait;
use cfx_types::{Address, H256, U256};
use parking_lot::RwLock;
use primitives::{EpochId, SponsorInfo, StorageLayout};
use std::sync::Arc;
