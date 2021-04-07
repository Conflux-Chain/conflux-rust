// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct State<StateDbStorage, Substate: SubstateMngTrait> {
    db: StateDbGeneric<StateDbStorage>,

    // State entries object-cache.
    cache: StateObjectCache,

    // A marker for the bound substate type.
    _substate_marker: PhantomData<Substate>,
}

impl<StateDbStorage: StorageStateTrait, Substate: SubstateMngTrait> StateTrait
    for State<StateDbStorage, Substate>
{
    type Substate = Substate;

    fn collect_ownership_changed(
        &mut self, _substate: &mut Self::Substate,
    ) -> Result<()> {
        unimplemented!()
    }

    fn settle_collateral_for_all(
        &mut self, _substate: &Self::Substate, _account_start_nonce: U256,
    ) -> Result<CollateralCheckResult> {
        unimplemented!()
    }

    fn collect_and_settle_collateral(
        &mut self, _original_sender: &Address, _storage_limit: &U256,
        _substate: &mut Self::Substate, _account_start_nonce: U256,
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

impl<StateDbStorage: StorageStateTrait, Substate: SubstateMngTrait>
    CheckpointTrait for State<StateDbStorage, Substate>
{
    fn checkpoint(&mut self) -> usize { self.db.checkpoint() }

    fn discard_checkpoint(&mut self) { self.db.discard_checkpoint(); }

    fn revert_to_checkpoint(&mut self) {
        // Drop the cache because of the revert.
        self.cache.clear();
        self.db.revert_to_checkpoint();
    }
}

impl<StateDbStorage: StorageStateTrait, Substate: SubstateMngTrait>
    StateOpsTrait for State<StateDbStorage, Substate>
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
            .get_account(address)?
            .as_ref()
            .map(|a| a.balance)
            .unwrap_or_default())
    }

    fn is_contract_with_code(&self, address: &Address) -> Result<bool> {
        if !address.is_contract_address() {
            return Ok(false);
        }
        Ok(self
            .get_account(address)?
            .as_ref()
            .map_or(false, |a| a.code_hash != KECCAK_EMPTY))
    }

    fn sponsor_for_gas(&self, address: &Address) -> Result<Option<Address>> {
        Ok(self
            .get_account(address)?
            .as_ref()
            .map_or(None, |a| maybe_address(&a.sponsor_info.sponsor_for_gas)))
    }

    fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> Result<Option<Address>> {
        Ok(self.get_account(address)?.as_ref().map_or(None, |a| {
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
            .get_account(address)?
            .as_ref()
            .map(|a| a.sponsor_info.clone()))
    }

    fn sponsor_gas_bound(&self, address: &Address) -> Result<U256> {
        Ok(self
            .get_account(address)?
            .as_ref()
            .map(|a| a.sponsor_info.sponsor_gas_bound)
            .unwrap_or_default())
    }

    fn sponsor_balance_for_gas(&self, address: &Address) -> Result<U256> {
        Ok(self
            .get_account(address)?
            .as_ref()
            .map(|a| a.sponsor_info.sponsor_balance_for_gas)
            .unwrap_or_default())
    }

    fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> Result<U256> {
        Ok(self
            .get_account(address)?
            .as_ref()
            .map(|a| a.sponsor_info.sponsor_balance_for_collateral)
            .unwrap_or_default())
    }

    fn set_admin(
        &mut self, contract_address: &Address, admin: &Address,
    ) -> Result<()> {
        self.modify_and_update_account(contract_address, None)?
            .as_mut()
            .map_or_else(
                || Err(ErrorKind::IncompleteDatabase(*contract_address).into()),
                |value| {
                    value.admin = *admin;
                    Ok(())
                },
            )
    }

    fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> Result<()> {
        if by.is_zero() {
            Ok(())
        } else {
            self.modify_and_update_account(address, None)?
                .as_mut()
                .map_or_else(
                    || Err(ErrorKind::IncompleteDatabase(*address).into()),
                    |value| {
                        value.sponsor_info.sponsor_balance_for_gas -= *by;
                        Ok(())
                    },
                )
        }
    }

    fn add_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> Result<()> {
        if by.is_zero() {
            Ok(())
        } else {
            self.modify_and_update_account(address, None)?
                .as_mut()
                .map_or_else(
                    || Err(ErrorKind::IncompleteDatabase(*address).into()),
                    |value| {
                        value.sponsor_info.sponsor_balance_for_gas += *by;
                        Ok(())
                    },
                )
        }
    }

    fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> Result<()> {
        if by.is_zero() {
            Ok(())
        } else {
            self.modify_and_update_account(address, None)?
                .as_mut()
                .map_or_else(
                    || Err(ErrorKind::IncompleteDatabase(*address).into()),
                    |value| {
                        value.sponsor_info.sponsor_balance_for_collateral -=
                            *by;
                        Ok(())
                    },
                )
        }
    }

    fn add_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> Result<()> {
        if by.is_zero() {
            Ok(())
        } else {
            self.modify_and_update_account(address, None)?
                .as_mut()
                .map_or_else(
                    || Err(ErrorKind::IncompleteDatabase(*address).into()),
                    |value| {
                        value.sponsor_info.sponsor_balance_for_collateral +=
                            *by;
                        Ok(())
                    },
                )
        }
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
            .get_account(address)?
            .as_ref()
            .map(|a| a.nonce)
            .unwrap_or_default())
    }

    fn init_code(
        &mut self, address: &Address, code: Vec<u8>, owner: Address,
    ) -> Result<()> {
        let code_address = CodeAddress(*address, keccak(&code));
        self.modify_and_update_code(&code_address, None)?
            .as_mut()
            .map_or_else(
                || Err(ErrorKind::IncompleteDatabase(*address).into()),
                |value| {
                    value.owner = owner;
                    value.code = Arc::new(code);
                    Ok(())
                },
            )
    }

    fn code_hash(&self, contract_address: &Address) -> Result<Option<H256>> {
        Ok(self
            .get_account(contract_address)?
            .as_ref()
            .map(|a| a.code_hash))
    }

    fn code_size(&self, contract_address: &Address) -> Result<Option<usize>> {
        Ok(self
            .get_code(contract_address)?
            .as_ref()
            .map(|code_info| code_info.code.len()))
    }

    fn code_owner(
        &self, contract_address: &Address,
    ) -> Result<Option<Address>> {
        Ok(self
            .get_code(contract_address)?
            .as_ref()
            .map(|code_info| code_info.owner))
    }

    fn code(&self, contract_address: &Address) -> Result<Option<Arc<Vec<u8>>>> {
        Ok(self
            .get_code(contract_address)?
            .as_ref()
            .map(|code_info| code_info.code.clone()))
    }

    fn staking_balance(&self, address: &Address) -> Result<U256> {
        Ok(self
            .get_account(address)?
            .as_ref()
            .map(|a| a.staking_balance)
            .unwrap_or_default())
    }

    fn collateral_for_storage(&self, address: &Address) -> Result<U256> {
        Ok(self
            .get_account(address)?
            .as_ref()
            .map(|a| a.collateral_for_storage)
            .unwrap_or_default())
    }

    fn admin(&self, address: &Address) -> Result<Address> {
        Ok(self
            .get_account(address)?
            .as_ref()
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

    fn deposit_list_length(&self, address: &Address) -> Result<usize> {
        Ok(self
            .get_deposit_list(address)?
            .as_ref()
            .map_or(0, |deposit_list| deposit_list.len()))
    }

    fn vote_stake_list_length(&self, address: &Address) -> Result<usize> {
        Ok(self
            .get_vote_stake_list(address)?
            .as_ref()
            .map_or(0, |vote_stake_list| vote_stake_list.len()))
    }

    fn clean_account(&mut self, _address: &Address) -> Result<()> {
        unimplemented!()
    }

    fn inc_nonce(
        &mut self, _address: &Address, _account_start_nonce: &U256,
    ) -> Result<()> {
        unimplemented!()
    }

    fn set_nonce(&mut self, _address: &Address, _nonce: &U256) -> Result<()> {
        unimplemented!()
    }

    fn sub_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: &mut CleanupMode,
    ) -> Result<()> {
        if !by.is_zero() {
            self.modify_and_update_account(address, None)?
                .as_mut()
                .map_or_else(
                    || Err(ErrorKind::IncompleteDatabase(*address).into()),
                    |value| {
                        value.balance = value.balance - *by;
                        Ok(())
                    },
                )?;
        }
        if let CleanupMode::TrackTouched(ref mut set) = *cleanup_mode {
            if self.exists(address)? {
                set.insert(*address);
            }
        }
        Ok(())
    }

    fn add_balance(
        &mut self, _address: &Address, _by: &U256, _cleanup_mode: CleanupMode,
        _account_start_nonce: U256,
    ) -> Result<()>
    {
        unimplemented!()
    }

    fn transfer_balance(
        &mut self, _from: &Address, _to: &Address, _by: &U256,
        _cleanup_mode: CleanupMode, _account_start_nonce: U256,
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

    fn exists(&self, address: &Address) -> Result<bool> {
        Ok(self.get_account(address)?.as_ref().is_none())
    }

    fn exists_and_not_null(&self, address: &Address) -> Result<bool> {
        Ok(self.get_account(address)?.as_ref().map_or(false, |a| {
            a.staking_balance.is_zero()
                && a.collateral_for_storage.is_zero()
                && a.nonce.is_zero()
                && a.code_hash == KECCAK_EMPTY
        }))
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

impl<StateDbStorage: StorageStateTrait, Substate: SubstateMngTrait>
    State<StateDbStorage, Substate>
{
    fn get_account(
        &self, address: &Address,
    ) -> Result<impl AsRef<NonCopy<Option<&CachedAccount>>>> {
        self.cache.get_account(address, &self.db)
    }

    fn get_code(
        &self, address: &Address,
    ) -> Result<impl AsRef<NonCopy<Option<&CodeInfo>>>> {
        self.cache.get_code(address, &self.db)
    }

    fn get_deposit_list(
        &self, address: &Address,
    ) -> Result<impl AsRef<NonCopy<Option<&DepositList>>>> {
        self.cache.get_deposit_list(address, &self.db)
    }

    fn get_vote_stake_list(
        &self, address: &Address,
    ) -> Result<impl AsRef<NonCopy<Option<&VoteStakeList>>>> {
        self.cache.get_vote_stake_list(address, &self.db)
    }

    fn modify_and_update_account<'a>(
        &'a mut self, address: &Address,
        debug_record: Option<&'a mut ComputeEpochDebugRecord>,
    ) -> Result<
        impl AsMut<
            ModifyAndUpdate<
                StateDbGeneric<StateDbStorage>,
                /* TODO: Key, */ CachedAccount,
            >,
        >,
    >
    {
        self.cache.modify_and_update_account(
            address,
            &mut self.db,
            debug_record,
        )
    }

    fn modify_and_update_code<'a>(
        &'a mut self, code_address: &CodeAddress,
        debug_record: Option<&'a mut ComputeEpochDebugRecord>,
    ) -> Result<
        impl AsMut<
            ModifyAndUpdate<
                StateDbGeneric<StateDbStorage>,
                /* TODO: Key, */ CodeInfo,
            >,
        >,
    >
    {
        self.cache.modify_and_update_code(
            code_address,
            &mut self.db,
            debug_record,
        )
    }
}

use crate::{
    cache_object::{CachedAccount, CodeAddress},
    maybe_address,
    state_object_cache::{ModifyAndUpdate, StateObjectCache},
    state_trait::{CheckpointTrait, StateOpsTrait},
    substate_trait::SubstateMngTrait,
    CleanupMode, CollateralCheckResult, StateTrait,
};
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_statedb::{
    ErrorKind, Result, StateDbCheckpointMethods, StateDbGeneric,
};
use cfx_storage::{utils::guarded_value::NonCopy, StorageStateTrait};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use keccak_hash::{keccak, KECCAK_EMPTY};
use primitives::{
    CodeInfo, DepositList, EpochId, SponsorInfo, StorageLayout, VoteStakeList,
};
use std::{marker::PhantomData, sync::Arc};
