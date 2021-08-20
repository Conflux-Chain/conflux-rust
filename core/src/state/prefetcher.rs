// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// pub state: &'a Arc<Mutex<State>>,
// pub address_waiters: Vec<(&'a Address, Arc<(Mutex<bool>, Condvar)>)>,
// pub canceled: AtomicBool,

pub fn prefetch_accounts_worker<StateDbStorage: StorageStateTrait>(
    state: &StateGenericIO<StateDbStorage>,
    accounts: Vec<(&Address, Arc<(Mutex<bool>, Condvar)>)>,
    cancel: &AtomicBool,
)
{
    for (address, waiter) in accounts {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        // Ignore db errors for now
        let _ = state.try_load(address);
        let (mtx, condvar) = waiter.deref();
        let mut ready = mtx.lock();
        *ready = true;
        condvar.notify_all();
    }
}

pub struct ExecutionStatePrefetcher {
    pub pool: ThreadPool,
}

impl ExecutionStatePrefetcher {
    pub fn new(
        num_threads: usize,
    ) -> Result<ExecutionStatePrefetcher, ThreadPoolBuildError> {
        Ok(ExecutionStatePrefetcher {
            pool: ThreadPoolBuilder::new().num_threads(num_threads).build()?,
        })
    }
}

pub struct StateWithWaiters<'a, StateDbStorage: StorageStateTrait> {
    pub io: &'a StateGenericIO<StateDbStorage>,
    pub info: &'a mut StateGenericInfo,
    pub address_waiters: HashMap<&'a Address, Arc<(Mutex<bool>, Condvar)>>,
}

impl<'a, StateDbStorage: StorageStateTrait>
    StateWithWaiters<'a, StateDbStorage>
{
    fn prepare_address(&self, addr: &'a Address) {
        if let Some(waiter) = self.address_waiters.get(addr) {
            let (mtx, condvar) = waiter.deref();
            let mut ready = mtx.lock();
            if !*ready {
                condvar.wait(&mut ready);
            }
        }
    }
}

impl<'a, StateDbStorage: StorageStateTrait>
    StateWithWaiters<'a, StateDbStorage>
{
}

// What we are doing here is actually inserting prepare_address before
// ensure_account_loaded
impl<'a, StateDbStorage: StorageStateTrait> StateOpsTxTrait
    for StateWithWaiters<'a, StateDbStorage>
{
    fn bump_block_number_accumulate_interest(&mut self) -> U256 {
        self.info.bump_block_number_accumulate_interest()
    }

    fn subtract_total_issued(&mut self, v: U256) {
        self.info.subtract_total_issued(v)
    }

    fn new_contract_with_admin(
        &mut self, contract: &Address, admin: &Address, balance: U256,
        nonce: U256, storage_layout: Option<StorageLayout>,
    ) -> DbResult<()>
    {
        self.io.new_contract_with_admin(
            &mut self.info,
            contract,
            admin,
            balance,
            nonce,
            storage_layout,
        )
    }

    fn balance(&self, address: &Address) -> DbResult<U256> {
        self.prepare_address(address);
        self.io.balance(address)
    }

    fn is_contract_with_code(&self, address: &Address) -> DbResult<bool> {
        if !address.is_contract_address() {
            return Ok(false);
        }
        self.prepare_address(address);
        self.io
            .ensure_account_loaded(address, RequireCache::None, |acc| {
                acc.map_or(false, |acc| acc.code_hash() != KECCAK_EMPTY)
            })
    }

    fn sponsor_for_gas(&self, address: &Address) -> DbResult<Option<Address>> {
        self.prepare_address(address);
        self.io.sponsor_for_gas(address)
    }

    fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        self.prepare_address(address);
        self.io.sponsor_for_collateral(address)
    }

    fn set_sponsor_for_gas(
        &mut self, address: &Address, sponsor: &Address,
        sponsor_balance: &U256, upper_bound: &U256,
    ) -> DbResult<()>
    {
        self.prepare_address(address);
        self.io.set_sponsor_for_gas(
            self.info,
            address,
            sponsor,
            sponsor_balance,
            upper_bound,
        )
    }

    fn set_sponsor_for_collateral(
        &mut self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
    ) -> DbResult<()> {
        self.prepare_address(address);
        self.io.set_sponsor_for_collateral(
            self.info,
            address,
            sponsor,
            sponsor_balance,
        )
    }

    fn sponsor_gas_bound(&self, address: &Address) -> DbResult<U256> {
        self.prepare_address(address);
        self.io.sponsor_gas_bound(address)
    }

    fn sponsor_balance_for_gas(&self, address: &Address) -> DbResult<U256> {
        self.prepare_address(address);
        self.io.sponsor_balance_for_gas(address)
    }

    fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256> {
        self.prepare_address(address);
        self.io.sponsor_balance_for_collateral(address)
    }

    fn set_admin(
        &mut self, contract_address: &Address, admin: &Address,
    ) -> DbResult<()> {
        self.io.set_admin(self.info, contract_address, admin)
    }

    fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        self.io.sub_sponsor_balance_for_gas(self.info, address, by)
    }

    fn add_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        self.io.add_sponsor_balance_for_gas(self.info, address, by)
    }

    fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        self.io
            .sub_sponsor_balance_for_collateral(self.info, address, by)
    }

    fn add_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        self.io
            .add_sponsor_balance_for_collateral(self.info, address, by)
    }

    fn check_commission_privilege(
        &self, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        self.prepare_address(&SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS);
        self.io.check_commission_privilege(contract_address, user)
    }

    fn add_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        self.io.add_commission_privilege(
            self.info,
            contract_address,
            contract_owner,
            user,
        )
    }

    fn remove_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        self.io.remove_commission_privilege(
            self.info,
            contract_address,
            contract_owner,
            user,
        )
    }

    fn nonce(&self, address: &Address) -> DbResult<U256> {
        self.prepare_address(address);
        self.io.nonce(address)
    }

    fn init_code(
        &mut self, address: &Address, code: Vec<u8>, owner: Address,
    ) -> DbResult<()> {
        self.io.init_code(self.info, address, code, owner)
    }

    fn code_hash(&self, address: &Address) -> DbResult<Option<H256>> {
        self.prepare_address(address);
        self.io.code_hash(address)
    }

    fn code_size(&self, address: &Address) -> DbResult<Option<usize>> {
        self.prepare_address(address);
        self.io.code_size(address)
    }

    fn code_owner(&self, address: &Address) -> DbResult<Option<Address>> {
        self.prepare_address(address);
        self.io.code_owner(address)
    }

    fn code(&self, address: &Address) -> DbResult<Option<Arc<Vec<u8>>>> {
        self.prepare_address(address);
        self.io.code(address)
    }

    fn staking_balance(&self, address: &Address) -> DbResult<U256> {
        self.prepare_address(address);
        self.io.staking_balance(address)
    }

    fn collateral_for_storage(&self, address: &Address) -> DbResult<U256> {
        self.prepare_address(address);
        self.io.collateral_for_storage(address)
    }

    fn admin(&self, address: &Address) -> DbResult<Address> {
        self.prepare_address(address);
        self.io.admin(address)
    }

    fn withdrawable_staking_balance(
        &self, address: &Address, current_block_number: u64,
    ) -> DbResult<U256> {
        self.prepare_address(address);
        self.io
            .withdrawable_staking_balance(address, current_block_number)
    }

    fn locked_staking_balance_at_block_number(
        &self, address: &Address, block_number: u64,
    ) -> DbResult<U256> {
        self.prepare_address(address);
        self.io
            .locked_staking_balance_at_block_number(address, block_number)
    }

    fn deposit_list_length(&self, address: &Address) -> DbResult<usize> {
        self.prepare_address(address);
        self.io.deposit_list_length(address)
    }

    fn vote_stake_list_length(&self, address: &Address) -> DbResult<usize> {
        self.prepare_address(address);
        self.io.vote_stake_list_length(address)
    }

    fn inc_nonce(
        &mut self, address: &Address, account_start_nonce: &U256,
    ) -> DbResult<()> {
        self.io.inc_nonce(self.info, address, account_start_nonce)
    }

    fn set_nonce(&mut self, address: &Address, nonce: &U256) -> DbResult<()> {
        self.io.set_nonce(self.info, address, nonce)
    }

    fn sub_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: &mut CleanupMode,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.io
                .require_exists(self.info, address, false)?
                .sub_balance(by);
        }

        if let CleanupMode::TrackTouched(ref mut set) = *cleanup_mode {
            if self.exists(address)? {
                // prepare_address here
                set.insert(*address);
            }
        }
        Ok(())
    }

    fn add_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: CleanupMode,
        account_start_nonce: U256,
    ) -> DbResult<()>
    {
        self.prepare_address(address);
        self.io.add_balance(
            self.info,
            address,
            by,
            cleanup_mode,
            account_start_nonce,
        )
    }

    fn transfer_balance(
        &mut self, from: &Address, to: &Address, by: &U256,
        cleanup_mode: CleanupMode, account_start_nonce: U256,
    ) -> DbResult<()>
    {
        self.io.transfer_balance(
            &mut self.info,
            from,
            to,
            by,
            cleanup_mode,
            account_start_nonce,
        )
    }

    fn deposit(
        &mut self, address: &Address, amount: &U256, current_block_number: u64,
    ) -> DbResult<()> {
        self.io
            .deposit(self.info, address, amount, current_block_number)
    }

    fn withdraw(&mut self, address: &Address, amount: &U256) -> DbResult<U256> {
        self.io.withdraw(self.info, address, amount)
    }

    fn vote_lock(
        &mut self, address: &Address, amount: &U256, unlock_block_number: u64,
    ) -> DbResult<()> {
        self.io
            .vote_lock(self.info, address, amount, unlock_block_number)
    }

    fn remove_expired_vote_stake_info(
        &mut self, address: &Address, current_block_number: u64,
    ) -> DbResult<()> {
        self.io.remove_expired_vote_stake_info(
            self.info,
            address,
            current_block_number,
        )
    }

    fn remove_contract(&mut self, address: &Address) -> DbResult<()> {
        self.io.remove_contract(self.info, address)
    }

    fn exists(&self, address: &Address) -> DbResult<bool> {
        self.prepare_address(address);
        self.io.exists(address)
    }

    fn exists_and_not_null(&self, address: &Address) -> DbResult<bool> {
        self.prepare_address(address);
        self.io.exists_and_not_null(address)
    }

    fn storage_at(&self, address: &Address, key: &[u8]) -> DbResult<U256> {
        self.prepare_address(address);
        self.io.storage_at(address, key)
    }

    fn set_storage(
        &mut self, address: &Address, key: Vec<u8>, value: U256, owner: Address,
    ) -> DbResult<()> {
        if self.storage_at(address, &key)? != value {
            // prepare_address here
            self.io
                .require_exists(self.info, address, false)?
                .set_storage(key, value, owner)
        }
        Ok(())
    }
}

impl<'a, StateDbStorage: StorageStateTrait> CheckpointTxDeltaTrait
    for StateWithWaiters<'a, StateDbStorage>
{
    fn checkpoint(&mut self) -> usize { self.info.checkpoint() }

    fn discard_checkpoint(&mut self) { self.info.discard_checkpoint() }

    fn revert_to_checkpoint(&mut self) {
        self.io.revert_to_checkpoint(&mut self.info)
    }
}

impl<'a, StateDbStorage: StorageStateTrait> CheckpointTxTrait
    for StateWithWaiters<'a, StateDbStorage>
{
}

impl<'a, StateDbStorage: StorageStateTrait> StateTxDeltaTrait
    for StateWithWaiters<'a, StateDbStorage>
{
    type Substate = Substate;

    fn collect_ownership_changed(
        &mut self, substate: &mut Self::Substate,
    ) -> DbResult<()> {
        self.io.collect_ownership_changed(self.info, substate)
    }

    fn settle_collateral_for_all(
        &mut self, substate: &Self::Substate, account_start_nonce: U256,
    ) -> DbResult<CollateralCheckResult> {
        self.io.settle_collateral_for_all(
            &mut self.info,
            substate,
            account_start_nonce,
        )
    }

    fn collect_and_settle_collateral(
        &mut self, original_sender: &Address, storage_limit: &U256,
        substate: &mut Substate, account_start_nonce: U256,
    ) -> DbResult<CollateralCheckResult>
    {
        self.io.collect_and_settle_collateral(
            &mut self.info,
            original_sender,
            storage_limit,
            substate,
            account_start_nonce,
        )
    }

    fn record_storage_and_whitelist_entries_release(
        &mut self, address: &Address, substate: &mut Self::Substate,
    ) -> DbResult<()> {
        self.io.record_storage_and_whitelist_entries_release(
            self.info, address, substate,
        )
    }
}

impl<'a, StateDbStorage: StorageStateTrait> StateTxTrait
    for StateWithWaiters<'a, StateDbStorage>
{
}

use crate::state::{
    DbResult, RequireCache, StateGenericIO, StateGenericInfo, StorageLayout,
    SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
};
use cfx_state::{
    state_trait::{
        CheckpointTxDeltaTrait, CheckpointTxTrait, StateOpsTxTrait,
        StateTxDeltaTrait, StateTxTrait,
    },
    CleanupMode, CollateralCheckResult,
};
use cfx_storage::{
    utils::deref_plus_impl_or_borrow_self::DerefPlusSelf, StorageStateTrait,
};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};

use keccak_hash::KECCAK_EMPTY;
use parking_lot::{Condvar, Mutex};
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use super::Substate;
