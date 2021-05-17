// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::U256;

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

    fn add_total_issued(&mut self, v: U256) {
        let new_total_issued = self.total_issued_tokens() + v;
        self.set_storage(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_TOKENS_KEY.to_vec(),
            new_total_issued,
            *STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
        )
        .unwrap();
    }

    fn subtract_total_issued(&mut self, v: U256) {
        let new_total_issued = self.total_issued_tokens() - v;
        self.set_storage(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_TOKENS_KEY.to_vec(),
            new_total_issued,
            *STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
        )
        .unwrap();
    }

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
        &self, contract_address: &Address, user_address: &Address,
    ) -> Result<bool> {
        Ok(self
            .get_commission_privilege(contract_address, user_address)?
            .as_ref()
            .map_or(false, |value| value.has_privilege()))
    }

    fn add_commission_privilege(
        &mut self, contract_address: Address, _contract_owner: Address,
        user: Address,
    ) -> Result<()>
    {
        self.modify_and_update_commission_privilege(
            &contract_address,
            &user,
            None,
        )?
        .as_mut()
        .map_or_else(
            || unreachable!(),
            |value| {
                value.add_privilege();
                Ok(())
            },
        )
    }

    fn remove_commission_privilege(
        &mut self, contract_address: Address, _contract_owner: Address,
        user: Address,
    ) -> Result<()>
    {
        self.modify_and_update_commission_privilege(
            &contract_address,
            &user,
            None,
        )?
        .as_mut()
        .map_or_else(
            || unreachable!(),
            |value| {
                value.remove_privilege();
                Ok(())
            },
        )
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
        let code_hash = keccak(&code);

        // Update the code hash.
        self.modify_and_update_account(address, None)?
            .as_mut()
            .map_or_else(
                || Err(ErrorKind::IncompleteDatabase(*address).into()),
                |value| {
                    value.code_hash = code_hash;
                    Ok(())
                },
            )?;

        // Set the code.
        self.require_or_set_code(*address, owner, code, None)
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
        &self, address: &Address, current_block_number: u64,
    ) -> Result<U256> {
        let staking_balance = self.staking_balance(address)?;
        match self.get_vote_stake_list(address)?.as_ref().deref() {
            None => Ok(staking_balance),
            Some(vote_stake_list) => Ok(vote_stake_list
                .withdrawable_staking_balance(
                    staking_balance,
                    current_block_number,
                )),
        }
    }

    fn locked_staking_balance_at_block_number(
        &self, address: &Address, current_block_number: u64,
    ) -> Result<U256> {
        let staking_balance = self.staking_balance(address)?;
        let withdrawable_staking_balance =
            self.withdrawable_staking_balance(address, current_block_number)?;
        Ok(staking_balance - withdrawable_staking_balance)
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
        &mut self, address: &Address, amount: &U256, unlock_block_number: u64,
    ) -> Result<()> {
        let staking_balance = self.staking_balance(address)?;
        if *amount > staking_balance {
            return Ok(());
        }
        self.modify_and_update_vote_stake_list(address, None)?
            .as_mut()
            .map_or_else(
                || unreachable!(),
                |vote_stake_list| {
                    vote_stake_list.vote_lock(*amount, unlock_block_number);
                    Ok(())
                },
            )
    }

    fn remove_expired_vote_stake_info(
        &mut self, address: &Address, current_block_number: u64,
    ) -> Result<()> {
        self.modify_and_update_vote_stake_list(address, None)?
            .as_mut()
            .map_or_else(
                || unreachable!(),
                |vote_stake_list| {
                    vote_stake_list
                        .remove_expired_vote_stake_info(current_block_number);
                    Ok(())
                },
            )
    }

    fn total_issued_tokens(&self) -> U256 {
        return self
            .storage_at(
                &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
                TOTAL_TOKENS_KEY,
            )
            .unwrap_or(U256::zero());
    }

    fn total_staking_tokens(&self) -> U256 {
        return self
            .storage_at(
                &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
                TOTAL_BANK_TOKENS_KEY,
            )
            .unwrap_or(U256::zero());
    }

    fn total_storage_tokens(&self) -> U256 {
        return self
            .storage_at(
                &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
                TOTAL_STORAGE_TOKENS_KEY,
            )
            .unwrap_or(U256::zero());
    }

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

    fn storage_at(&self, address: &Address, key: &[u8]) -> Result<U256> {
        Ok(self
            .get_storage(address, key)?
            .as_ref()
            .map_or(U256::zero(), |a| a.value))
    }

    fn set_storage(
        &mut self, address: &Address, key: Vec<u8>, value: U256, owner: Address,
    ) -> Result<()> {
        self.modify_and_update_storage(address, &*key, None)?
            .as_mut()
            .map_or_else(
                || unreachable!(),
                |entry| {
                    entry.value = value;
                    if owner == *address {
                        entry.owner = None
                    } else {
                        entry.owner = Some(owner)
                    }
                    Ok(())
                },
            )
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

    fn get_commission_privilege(
        &self, contract_address: &Address, user_address: &Address,
    ) -> Result<impl AsRef<NonCopy<Option<&CachedCommissionPrivilege>>>> {
        self.cache.get_commission_privilege(
            contract_address,
            user_address,
            &self.db,
        )
    }

    fn modify_and_update_commission_privilege<'a>(
        &'a mut self, contract_address: &Address, user_address: &Address,
        debug_record: Option<&'a mut ComputeEpochDebugRecord>,
    ) -> Result<
        impl AsMut<
            ModifyAndUpdate<
                StateDbGeneric<StateDbStorage>,
                /* TODO: Key, */ CachedCommissionPrivilege,
            >,
        >,
    >
    {
        self.cache.modify_and_update_commission_privilege(
            contract_address,
            user_address,
            &mut self.db,
            debug_record,
        )
    }

    fn get_storage(
        &self, address: &Address, key: &[u8],
    ) -> Result<impl AsRef<NonCopy<Option<&StorageValue>>>> {
        self.cache.get_storage(address, key, &self.db)
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

    fn modify_and_update_vote_stake_list<'a>(
        &'a mut self, address: &Address,
        debug_record: Option<&'a mut ComputeEpochDebugRecord>,
    ) -> Result<
        impl AsMut<
            ModifyAndUpdate<
                StateDbGeneric<StateDbStorage>,
                /* TODO: Key, */ VoteStakeList,
            >,
        >,
    >
    {
        self.cache.modify_and_update_vote_stake_list(
            address,
            &mut self.db,
            debug_record,
        )
    }

    fn modify_and_update_storage<'a>(
        &'a mut self, address: &Address, key: &[u8],
        debug_record: Option<&'a mut ComputeEpochDebugRecord>,
    ) -> Result<
        impl AsMut<ModifyAndUpdate<StateDbGeneric<StateDbStorage>, StorageValue>>,
    >
    {
        self.cache.modify_and_update_storage(
            address,
            key,
            &mut self.db,
            debug_record,
        )
    }

    fn require_or_set_code<'a>(
        &'a mut self, address: Address, code_owner: Address, code: Vec<u8>,
        debug_record: Option<&'a mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        self.cache.require_or_set_code(
            address,
            code_owner,
            code,
            &mut self.db,
            debug_record,
        )
    }
}

use crate::{
    cache_object::{CachedAccount, CachedCommissionPrivilege},
    maybe_address,
    state_object_cache::{ModifyAndUpdate, StateObjectCache},
    state_trait::{CheckpointTrait, StateOpsTrait},
    substate_trait::SubstateMngTrait,
    CleanupMode, CollateralCheckResult, StateTrait,
};
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_parameters::internal_contract_addresses::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS;
use cfx_statedb::{
    ErrorKind, Result, StateDbCheckpointMethods, StateDbGeneric,
    TOTAL_BANK_TOKENS_KEY, TOTAL_STORAGE_TOKENS_KEY, TOTAL_TOKENS_KEY,
};
use cfx_storage::{utils::guarded_value::NonCopy, StorageStateTrait};
use cfx_types::{address_util::AddressUtil, Address, H256};
use keccak_hash::{keccak, KECCAK_EMPTY};
use primitives::{
    CodeInfo, DepositList, EpochId, SponsorInfo, StorageLayout, StorageValue,
    VoteStakeList,
};
use std::{marker::PhantomData, ops::Deref, sync::Arc};
