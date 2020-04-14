// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use self::account_entry::{AccountEntry, AccountState};
use crate::{
    bytes::Bytes,
    executive::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    hash::KECCAK_EMPTY,
    parameters::staking::*,
    statedb::{ErrorKind as DbErrorKind, Result as DbResult, StateDb},
    storage::StateRootWithAuxInfo,
    transaction_pool::SharedTransactionPool,
    vm_factory::VmFactory,
};
use cfx_types::{Address, H256, U256};
use primitives::{Account, EpochId, StorageKey, StorageLayout, StorageValue};
use std::{
    cell::{RefCell, RefMut},
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};

#[cfg(test)]
mod account_entry_tests;
#[cfg(test)]
mod state_tests;

mod account_entry;
mod substate;

pub use self::{account_entry::OverlayAccount, substate::Substate};
//use crate::parameters::block::ESTIMATED_MAX_BLOCK_SIZE_IN_TRANSACTION_COUNT;

#[derive(Copy, Clone)]
enum RequireCache {
    None,
    CodeSize,
    Code,
}

/// Mode of dealing with null accounts.
#[derive(PartialEq)]
pub enum CleanupMode<'a> {
    /// Create accounts which would be null.
    ForceCreate,
    /// Don't delete null accounts upon touching, but also don't create them.
    NoEmpty,
    /// Mark all touched accounts.
    /// TODO: We have not implemented the correct behavior of TrackTouched for
    /// internal Contracts.
    TrackTouched(&'a mut HashSet<Address>),
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum CollateralCheckResult {
    ExceedStorageLimit { limit: U256, required: U256 },
    NotEnoughBalance { required: U256, got: U256 },
    Valid,
}

#[derive(Copy, Clone, Debug)]
struct StakingState {
    // This is the total number of CFX issued.
    total_issued_tokens: U256,
    // This is the total number of CFX used as staking.
    total_staking_tokens: U256,
    // This is the total number of CFX used as collateral.
    total_storage_tokens: U256,
    // This is the interest rate per block.
    interest_rate_per_block: U256,
    // This is the accumulated interest rate.
    accumulate_interest_rate: U256,
}

pub struct State {
    db: StateDb,

    cache: RefCell<HashMap<Address, AccountEntry>>,
    staking_state_checkpoints: RefCell<Vec<StakingState>>,
    checkpoints: RefCell<Vec<HashMap<Address, Option<AccountEntry>>>>,
    account_start_nonce: U256,
    staking_state: StakingState,
    // This is the total number of blocks executed so far. It is the same as
    // the `number` entry in EVM Environment.
    block_number: u64,
    vm: VmFactory,
}

impl State {
    pub fn new(db: StateDb, vm: VmFactory, block_number: u64) -> Self {
        let annual_interest_rate =
            db.get_annual_interest_rate().expect("no db error");
        let accumulate_interest_rate =
            db.get_accumulate_interest_rate().expect("no db error");
        let total_issued_tokens =
            db.get_total_issued_tokens().expect("No db error");
        let total_staking_tokens =
            db.get_total_staking_tokens().expect("No db error");
        let total_storage_tokens =
            db.get_total_storage_tokens().expect("No db error");
        /*
        let account_start_nonce = (block_number
            * ESTIMATED_MAX_BLOCK_SIZE_IN_TRANSACTION_COUNT as u64)
            .into();
        */
        let account_start_nonce = 0.into();
        State {
            db,
            cache: RefCell::new(HashMap::new()),
            staking_state_checkpoints: RefCell::new(Vec::new()),
            checkpoints: RefCell::new(Vec::new()),
            account_start_nonce,
            staking_state: StakingState {
                total_issued_tokens,
                total_staking_tokens,
                total_storage_tokens,
                interest_rate_per_block: annual_interest_rate
                    / U256::from(BLOCKS_PER_YEAR),
                accumulate_interest_rate,
            },
            block_number,
            vm,
        }
    }

    /// Increase block number and calculate the current secondary reward.
    pub fn increase_block_number(&mut self) -> U256 {
        assert!(self.staking_state_checkpoints.borrow().is_empty());
        self.block_number += 1;
        //self.account_start_nonce +=
        //    ESTIMATED_MAX_BLOCK_SIZE_IN_TRANSACTION_COUNT.into();
        self.staking_state.accumulate_interest_rate =
            self.staking_state.accumulate_interest_rate
                * (*INTEREST_RATE_PER_BLOCK_SCALE
                    + self.staking_state.interest_rate_per_block)
                / *INTEREST_RATE_PER_BLOCK_SCALE;
        let secondary_reward = self.staking_state.total_storage_tokens
            * self.staking_state.interest_rate_per_block
            / *INTEREST_RATE_PER_BLOCK_SCALE;
        // TODO: the interest from tokens other than storage and staking should
        // send to public fund.
        secondary_reward
    }

    /// Maintain `total_issued_tokens`, both secondary reward and primary reward
    /// are included.
    pub fn add_block_rewards(&mut self, rewards: U256) {
        assert!(self.staking_state_checkpoints.borrow().is_empty());
        self.staking_state.total_issued_tokens += rewards;
    }

    /// Get a VM factory that can execute on this state.
    pub fn vm_factory(&self) -> VmFactory { self.vm.clone() }

    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index.
    pub fn checkpoint(&mut self) -> usize {
        self.staking_state_checkpoints
            .borrow_mut()
            .push(self.staking_state.clone());
        let checkpoints = self.checkpoints.get_mut();
        let index = checkpoints.len();
        checkpoints.push(HashMap::new());
        index
    }

    pub fn check_collateral_for_storage(
        &mut self, storage_owner: &Address, storage_limit: &U256,
        substate: &mut Substate,
    ) -> DbResult<CollateralCheckResult>
    {
        let mut collateral_for_storage_sub = HashMap::new();
        let mut collateral_for_storage_inc = HashMap::new();
        if let Some(checkpoint) = self.checkpoints.borrow().last() {
            for address in checkpoint.keys() {
                if let Some(ref mut maybe_acc) = self
                    .cache
                    .borrow_mut()
                    .get_mut(address)
                    .filter(|x| x.is_dirty())
                {
                    if let Some(ref mut acc) = maybe_acc.account.as_mut() {
                        let ownership_delta =
                            acc.commit_ownership_change(&self.db);
                        for (addr, (inc, sub)) in ownership_delta {
                            if inc > 0 {
                                *collateral_for_storage_inc
                                    .entry(addr)
                                    .or_insert(0) += inc;
                            }
                            if sub > 0 {
                                *collateral_for_storage_sub
                                    .entry(addr)
                                    .or_insert(0) += sub;
                            }
                        }
                    }
                }
            }
        }
        for (addr, sub) in &collateral_for_storage_sub {
            let delta = U256::from(*sub) * *COLLATERAL_PER_STORAGE_KEY;
            assert!(self.exists(addr)?);
            self.sub_collateral_for_storage(addr, &delta)?;
        }
        for (addr, inc) in &collateral_for_storage_inc {
            let delta = U256::from(*inc) * *COLLATERAL_PER_STORAGE_KEY;
            if self.is_contract(addr) {
                let sponsor_balance =
                    self.sponsor_balance_for_collateral(addr)?;
                // sponsor_balance is not enough to cover storage incremental.
                if delta > sponsor_balance {
                    return Ok(CollateralCheckResult::NotEnoughBalance {
                        required: delta,
                        got: sponsor_balance,
                    });
                }
            } else {
                let balance = self.balance(addr).expect("no db error");
                // balance is not enough to cover storage incremental.
                if delta > balance {
                    return Ok(CollateralCheckResult::NotEnoughBalance {
                        required: delta,
                        got: balance,
                    });
                }
            }
            self.add_collateral_for_storage(addr, &delta)?
        }

        let collateral_for_storage =
            self.collateral_for_storage(storage_owner)?;
        if collateral_for_storage > *storage_limit {
            return Ok(CollateralCheckResult::ExceedStorageLimit {
                limit: *storage_limit,
                required: collateral_for_storage,
            });
        } else {
            for (addr, sub) in collateral_for_storage_sub {
                *substate.storage_released.entry(addr).or_insert(0) += sub * 64;
            }
            for (addr, inc) in collateral_for_storage_inc {
                *substate.storage_collateralized.entry(addr).or_insert(0) +=
                    inc * 64;
            }
            Ok(CollateralCheckResult::Valid)
        }
    }

    /// Merge last checkpoint with previous.
    /// Caller should make sure the function
    /// `check_collateral_for_storage()` was called before calling
    /// this function.
    pub fn discard_checkpoint(&mut self) {
        // merge with previous checkpoint
        let last = self.checkpoints.get_mut().pop();
        if let Some(mut checkpoint) = last {
            self.staking_state_checkpoints.borrow_mut().pop();
            if let Some(ref mut prev) = self.checkpoints.get_mut().last_mut() {
                if prev.is_empty() {
                    **prev = checkpoint;
                } else {
                    for (k, v) in checkpoint.drain() {
                        prev.entry(k).or_insert(v);
                    }
                }
            }
        }
    }

    /// Revert to the last checkpoint and discard it.
    pub fn revert_to_checkpoint(&mut self) {
        if let Some(mut checkpoint) = self.checkpoints.get_mut().pop() {
            self.staking_state = self
                .staking_state_checkpoints
                .borrow_mut()
                .pop()
                .expect("staking_state_checkpoint should exist");
            for (k, v) in checkpoint.drain() {
                match v {
                    Some(v) => match self.cache.get_mut().entry(k) {
                        Entry::Occupied(mut e) => {
                            e.get_mut().overwrite_with(v);
                        }
                        Entry::Vacant(e) => {
                            e.insert(v);
                        }
                    },
                    None => {
                        if let Entry::Occupied(e) =
                            self.cache.get_mut().entry(k)
                        {
                            if e.get().is_dirty() {
                                e.remove();
                            }
                        }
                    }
                }
            }
        }
    }

    fn insert_cache(&self, address: &Address, account: AccountEntry) {
        let is_dirty = account.is_dirty();
        let old_value = self.cache.borrow_mut().insert(*address, account);
        if is_dirty {
            if let Some(ref mut checkpoint) =
                self.checkpoints.borrow_mut().last_mut()
            {
                checkpoint.entry(*address).or_insert(old_value);
            }
        }
    }

    fn note_cache(&self, address: &Address) {
        if let Some(ref mut checkpoint) =
            self.checkpoints.borrow_mut().last_mut()
        {
            checkpoint.entry(*address).or_insert_with(|| {
                self.cache
                    .borrow()
                    .get(address)
                    .map(AccountEntry::clone_dirty)
            });
        }
    }

    pub fn new_contract_with_admin(
        &mut self, contract: &Address, admin: &Address, balance: U256,
        nonce_offset: U256,
    ) -> DbResult<()>
    {
        self.insert_cache(
            contract,
            AccountEntry::new_dirty(Some(
                OverlayAccount::new_contract_with_admin(
                    contract,
                    balance,
                    self.account_start_nonce + nonce_offset,
                    true,
                    admin,
                ),
            )),
        );
        Ok(())
    }

    pub fn new_contract(
        &mut self, contract: &Address, balance: U256, nonce_offset: U256,
    ) -> DbResult<()> {
        self.insert_cache(
            contract,
            AccountEntry::new_dirty(Some(OverlayAccount::new_contract(
                contract,
                balance,
                self.account_start_nonce + nonce_offset,
                true,
            ))),
        );
        Ok(())
    }

    pub fn balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.balance())
        })
    }

    pub fn is_contract(&self, address: &Address) -> bool {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| acc.is_contract())
        })
        .unwrap_or(false)
    }

    pub fn sponsor_for_gas(&self, address: &Address) -> DbResult<Address> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(Address::zero(), |acc| {
                acc.sponsor_info().sponsor_for_gas
            })
        })
    }

    pub fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Address> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(Address::zero(), |acc| {
                acc.sponsor_info().sponsor_for_collateral
            })
        })
    }

    pub fn set_sponsor_for_gas(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    ) -> DbResult<()>
    {
        if *sponsor != self.sponsor_for_gas(address)?
            || *sponsor_balance != self.sponsor_balance_for_gas(address)?
        {
            self.require(address, false).map(|mut x| {
                x.set_sponsor_for_gas(sponsor, sponsor_balance, upper_bound)
            })
        } else {
            Ok(())
        }
    }

    pub fn set_sponsor_for_collateral(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
    ) -> DbResult<()> {
        if *sponsor != self.sponsor_for_collateral(address)?
            || *sponsor_balance
                != self.sponsor_balance_for_collateral(address)?
        {
            self.require(address, false).map(|mut x| {
                x.set_sponsor_for_collateral(sponsor, sponsor_balance)
            })
        } else {
            Ok(())
        }
    }

    pub fn sponsor_gas_bound(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| acc.sponsor_info().sponsor_gas_bound)
        })
    }

    pub fn sponsor_balance_for_gas(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| {
                acc.sponsor_info().sponsor_balance_for_gas
            })
        })
    }

    pub fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| {
                acc.sponsor_info().sponsor_balance_for_collateral
            })
        })
    }

    pub fn set_admin(
        &mut self, requester: &Address, contract_address: &Address,
        admin: &Address,
    ) -> DbResult<()>
    {
        if self.ensure_cached(contract_address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| {
                acc.is_contract()
                    && (acc.admin().is_zero() || acc.admin() == requester)
                    && acc.admin() != admin
            })
        })? {
            self.require(&contract_address, false)?
                .set_admin(requester, admin);
        }
        Ok(())
    }

    pub fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?
                .sub_sponsor_balance_for_gas(by);
        }
        Ok(())
    }

    pub fn add_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?
                .add_sponsor_balance_for_gas(by);
        }
        Ok(())
    }

    pub fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?
                .sub_sponsor_balance_for_collateral(by);
        }
        Ok(())
    }

    pub fn add_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?
                .add_sponsor_balance_for_collateral(by);
        }
        Ok(())
    }

    pub fn check_commission_privilege(
        &self, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        match self.ensure_cached(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            RequireCache::None,
            |acc| {
                acc.map_or(Ok(false), |acc| {
                    acc.check_commission_privilege(
                        &self.db,
                        contract_address,
                        user,
                    )
                })
            },
        ) {
            Ok(Ok(bool)) => Ok(bool),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e),
        }
    }

    pub fn add_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        info!("add_commission_privilege contract_address: {:?}, contract_owner: {:?}, user: {:?}", contract_address, contract_owner, user);

        let mut account =
            self.require(&SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS, false)?;
        Ok(account.add_commission_privilege(
            contract_address,
            contract_owner,
            user,
        ))
    }

    pub fn remove_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        let mut account =
            self.require(&SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS, false)?;
        Ok(account.remove_commission_privilege(
            contract_address,
            contract_owner,
            user,
        ))
    }

    pub fn nonce(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.nonce())
        })
    }

    pub fn code_hash(&self, address: &Address) -> DbResult<Option<H256>> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.and_then(|acc| Some(acc.code_hash()))
        })
    }

    pub fn code_size(&self, address: &Address) -> DbResult<Option<usize>> {
        self.ensure_cached(address, RequireCache::CodeSize, |acc| {
            acc.and_then(|acc| acc.code_size())
        })
    }

    pub fn code_owner(&self, address: &Address) -> DbResult<Option<Address>> {
        self.ensure_cached(address, RequireCache::Code, |acc| {
            acc.as_ref().map_or(None, |acc| acc.code_owner())
        })
    }

    pub fn code(&self, address: &Address) -> DbResult<Option<Arc<Bytes>>> {
        self.ensure_cached(address, RequireCache::Code, |acc| {
            acc.as_ref().map_or(None, |acc| acc.code())
        })
    }

    pub fn staking_balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.staking_balance())
        })
    }

    pub fn collateral_for_storage(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| {
                *account.collateral_for_storage()
            })
        })
    }

    pub fn admin(&self, address: &Address) -> DbResult<Address> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(Address::zero(), |acc| *acc.admin())
        })
    }

    pub fn withdrawable_staking_balance(
        &self, address: &Address,
    ) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| {
                *account.withdrawable_staking_balance()
            })
        })
    }

    pub fn inc_nonce(&mut self, address: &Address) -> DbResult<()> {
        self.require(address, false).map(|mut x| x.inc_nonce())
    }

    pub fn sub_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: &mut CleanupMode,
    ) -> DbResult<()> {
        if !by.is_zero() || !self.exists(address)? {
            self.require(address, false)?.sub_balance(by);
        }
        if let CleanupMode::TrackTouched(ref mut set) = *cleanup_mode {
            set.insert(*address);
        }
        Ok(())
    }

    pub fn add_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: CleanupMode,
    ) -> DbResult<()> {
        if !by.is_zero()
            || (cleanup_mode == CleanupMode::ForceCreate
                && !self.exists(address)?)
        {
            self.require(address, false)?.add_balance(by);
        } else if let CleanupMode::TrackTouched(set) = cleanup_mode {
            if self.exists(address)? {
                set.insert(*address);

                // I don't know why sub_balance and add_balance have different
                // behaviors here in Parity.
                // self.exists(address) has loaded address to self.cache.

                // Stop marking address as dirty here.
                // self.touch(address)?;
            }
        }
        Ok(())
    }

    /// Caller should make sure that staking_balance for this account is
    /// sufficient enough.
    pub fn add_collateral_for_storage(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?.add_collateral_for_storage(by);
            self.staking_state.total_storage_tokens += *by;
        }
        Ok(())
    }

    pub fn sub_collateral_for_storage(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?.sub_collateral_for_storage(by);
            self.staking_state.total_storage_tokens -= *by;
        }
        Ok(())
    }

    pub fn deposit(
        &mut self, address: &Address, amount: &U256,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            self.require(address, false)?.deposit(
                *amount,
                self.staking_state.accumulate_interest_rate,
                self.block_number,
            );
            self.staking_state.total_staking_tokens += *amount;
        }
        Ok(())
    }

    pub fn withdraw(
        &mut self, address: &Address, amount: &U256,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            let interest = self
                .require(address, false)?
                .withdraw(*amount, self.staking_state.accumulate_interest_rate);
            // the interest will be put in balance.
            self.staking_state.total_issued_tokens += interest;
            self.staking_state.total_staking_tokens -= *amount;
        }
        Ok(())
    }

    pub fn lock(
        &mut self, address: &Address, amount: &U256, duration_in_day: u64,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            self.require(address, false)?.lock(
                *amount,
                self.block_number + duration_in_day * BLOCKS_PER_DAY,
            );
        }
        Ok(())
    }

    pub fn annual_interest_rate(&self) -> U256 {
        self.staking_state.interest_rate_per_block * U256::from(BLOCKS_PER_YEAR)
    }

    pub fn set_annual_interest_rate(&mut self, annual_interest_rate: U256) {
        self.staking_state.interest_rate_per_block =
            annual_interest_rate / U256::from(BLOCKS_PER_YEAR);
    }

    pub fn accumulate_interest_rate(&self) -> &U256 {
        &self.staking_state.accumulate_interest_rate
    }

    pub fn block_number(&self) -> u64 { self.block_number }

    pub fn total_issued_tokens(&self) -> &U256 {
        &self.staking_state.total_issued_tokens
    }

    pub fn total_staking_tokens(&self) -> &U256 {
        &self.staking_state.total_staking_tokens
    }

    pub fn total_storage_tokens(&self) -> &U256 {
        &self.staking_state.total_storage_tokens
    }

    #[allow(dead_code)]
    fn touch(&mut self, address: &Address) -> DbResult<()> {
        self.require(address, false)?;
        Ok(())
    }

    /// Load required account data from the databases. Returns whether the
    /// cache succeeds.
    fn update_account_cache(
        require: RequireCache, account: &mut OverlayAccount, db: &StateDb,
    ) -> bool {
        if let RequireCache::None = require {
            return true;
        }

        trace!("update_account_cache account={:?}", account);
        if account.is_cached() {
            return true;
        }

        match require {
            RequireCache::None => true,
            RequireCache::Code | RequireCache::CodeSize => {
                account.cache_code(db).is_some()
            }
        }
    }

    fn commit_staking_state(&mut self) -> DbResult<()> {
        self.db.set_annual_interest_rate(
            &(self.staking_state.interest_rate_per_block
                * U256::from(BLOCKS_PER_YEAR)),
        )?;
        self.db.set_accumulate_interest_rate(
            &self.staking_state.accumulate_interest_rate,
        )?;
        self.db
            .set_total_issued_tokens(&self.staking_state.total_issued_tokens)?;
        self.db.set_total_staking_tokens(
            &self.staking_state.total_staking_tokens,
        )?;
        self.db.set_total_storage_tokens(
            &self.staking_state.total_storage_tokens,
        )?;
        Ok(())
    }

    /// Assume that only contract with zero `collateral_for_storage` will be
    /// killed.
    fn recycle_storage(
        &mut self, killed_addresses: Vec<Address>,
    ) -> DbResult<()> {
        for address in killed_addresses {
            self.db.delete(StorageKey::new_account_key(&address))?;
            let storages_opt = self
                .db
                .delete_all(StorageKey::new_storage_root_key(&address))?;
            self.db
                .delete_all(StorageKey::new_code_root_key(&address))?;
            if let Some(storage_key_value) = storages_opt {
                for (key, value) in storage_key_value {
                    if let StorageKey::StorageKey { .. } =
                        StorageKey::from_delta_mpt_key(&key[..])
                    {
                        let storage_value =
                            rlp::decode::<StorageValue>(value.as_ref())?;
                        assert!(self
                            .exists(&storage_value.owner)
                            .expect("no db error"));
                        self.sub_collateral_for_storage(
                            &storage_value.owner,
                            &COLLATERAL_PER_STORAGE_KEY,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn commit(
        &mut self, epoch_id: EpochId,
    ) -> DbResult<StateRootWithAuxInfo> {
        debug!("Commit epoch[{}]", epoch_id);
        assert!(self.checkpoints.borrow().is_empty());
        assert!(self.staking_state_checkpoints.borrow().is_empty());

        let mut killed_addresses = Vec::new();
        {
            let accounts = self.cache.borrow();
            for (address, entry) in accounts.iter() {
                if entry.is_dirty() && entry.account.is_none() {
                    killed_addresses.push(*address);
                }
            }
        }
        self.recycle_storage(killed_addresses)?;
        self.commit_staking_state()?;

        let mut accounts = self.cache.borrow_mut();
        for (address, ref mut entry) in accounts
            .iter_mut()
            .filter(|&(_, ref entry)| entry.is_dirty())
        {
            entry.state = AccountState::Committed;
            if let Some(ref mut account) = entry.account {
                account.commit(&mut self.db)?;
                self.db.set::<Account>(
                    StorageKey::new_account_key(address),
                    &account.as_account(),
                )?;
            }
        }
        Ok(self.db.commit(epoch_id)?)
    }

    pub fn commit_and_notify(
        &mut self, epoch_id: EpochId, txpool: &SharedTransactionPool,
    ) -> DbResult<StateRootWithAuxInfo> {
        assert!(self.checkpoints.borrow().is_empty());

        let mut accounts_for_txpool = vec![];

        let mut killed_addresses = Vec::new();
        {
            let accounts = self.cache.borrow();
            for (address, entry) in accounts.iter() {
                if entry.is_dirty() && entry.account.is_none() {
                    killed_addresses.push(*address);
                }
            }
        }
        self.recycle_storage(killed_addresses)?;
        self.commit_staking_state()?;

        let mut accounts = self.cache.borrow_mut();
        debug!("Notify epoch[{}]", epoch_id);
        let mut sorted_dirty_addresses = accounts
            .iter()
            .filter_map(|(address, entry)| {
                if entry.is_dirty() {
                    Some(address.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        sorted_dirty_addresses.sort();
        for address in &sorted_dirty_addresses {
            let entry = accounts.get_mut(address).unwrap();
            entry.state = AccountState::Committed;
            if let Some(ref mut account) = entry.account {
                accounts_for_txpool.push(account.as_account());
                account.commit(&mut self.db)?;
                self.db.set::<Account>(
                    StorageKey::new_account_key(address),
                    &account.as_account(),
                )?;
            }
        }
        let result = self.db.commit(epoch_id)?;
        {
            let txpool_clone = txpool.clone();
            std::thread::Builder::new()
                .name("txpool_update_state".into())
                .spawn(move || {
                    txpool_clone.notify_modified_accounts(accounts_for_txpool);
                })
                .expect("can not notify tx pool to start state");
        }
        Ok(result)
    }

    pub fn init_code(
        &mut self, address: &Address, code: Bytes, owner: Address,
    ) -> DbResult<()> {
        self.require_or_from(
            address,
            true,
            || {
                OverlayAccount::new_contract(
                    address,
                    0.into(),
                    self.account_start_nonce,
                    false,
                )
            },
            |_| {},
        )?
        .init_code(code, owner);
        Ok(())
    }

    pub fn transfer_balance(
        &mut self, from: &Address, to: &Address, by: &U256,
        mut cleanup_mode: CleanupMode,
    ) -> DbResult<()>
    {
        self.sub_balance(from, by, &mut cleanup_mode)?;
        self.add_balance(to, by, cleanup_mode)?;
        Ok(())
    }

    pub fn kill_account(&mut self, address: &Address) {
        self.insert_cache(address, AccountEntry::new_dirty(None))
    }

    pub fn exists(&self, address: &Address) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::None, |acc| acc.is_some())
    }

    pub fn exists_and_not_null(&self, address: &Address) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| !acc.is_null())
        })
    }

    pub fn exists_and_has_code_or_nonce(
        &self, address: &Address,
    ) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::CodeSize, |acc| {
            acc.map_or(false, |acc| {
                acc.code_hash() != KECCAK_EMPTY
                    || *acc.nonce() != self.account_start_nonce
            })
        })
    }

    pub fn kill_garbage(
        &mut self, touched: &HashSet<Address>, remove_empty_touched: bool,
        min_balance: &Option<U256>, kill_contracts: bool,
    ) -> DbResult<()>
    {
        // TODO: consider both balance and staking_balance
        let to_kill: HashSet<_> = {
            self.cache
                .borrow()
                .iter()
                .filter_map(|(address, ref entry)| {
                    if touched.contains(address)
                        && ((remove_empty_touched
                            && entry.exists_and_is_null())
                            || (min_balance.map_or(false, |ref balance| {
                                entry.account.as_ref().map_or(false, |acc| {
                                    (acc.is_basic() || kill_contracts)
                                        && acc.balance() < balance
                                        && entry
                                            .old_balance
                                            .as_ref()
                                            .map_or(false, |b| {
                                                acc.balance() < b
                                            })
                                })
                            })))
                    {
                        Some(address.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };
        for address in to_kill {
            self.kill_account(&address);
        }

        Ok(())
    }

    pub fn storage_at(&self, address: &Address, key: &H256) -> DbResult<H256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(H256::zero(), |account| {
                account.storage_at(&self.db, key).unwrap_or(H256::zero())
            })
        })
    }

    #[cfg(test)]
    pub fn original_storage_at(
        &self, address: &Address, key: &H256,
    ) -> DbResult<H256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(H256::zero(), |account| {
                account
                    .original_storage_at(&self.db, key)
                    .unwrap_or(H256::zero())
            })
        })
    }

    /// Get the value of storage at a specific checkpoint.
    /// TODO: Remove this function since it is not used outside.
    #[cfg(test)]
    pub fn checkpoint_storage_at(
        &self, start_checkpoint_index: usize, address: &Address, key: &H256,
    ) -> DbResult<Option<H256>> {
        #[derive(Debug)]
        enum ReturnKind {
            OriginalAt,
            SameAsNext,
        }

        let kind = {
            let checkpoints = self.checkpoints.borrow();

            if start_checkpoint_index >= checkpoints.len() {
                return Ok(None);
            }

            let mut kind = None;

            for checkpoint in checkpoints.iter().skip(start_checkpoint_index) {
                match checkpoint.get(address) {
                    Some(Some(AccountEntry {
                        account: Some(ref account),
                        ..
                    })) => {
                        if let Some(value) = account.cached_storage_at(key) {
                            return Ok(Some(value));
                        } else if account.reset_storage() {
                            return Ok(Some(H256::zero()));
                        } else {
                            kind = Some(ReturnKind::OriginalAt);
                            break;
                        }
                    }
                    Some(Some(AccountEntry { account: None, .. })) => {
                        return Ok(Some(H256::zero()));
                    }
                    Some(None) => {
                        kind = Some(ReturnKind::OriginalAt);
                        break;
                    }
                    // This key does not have a checkpoint entry.
                    None => {
                        kind = Some(ReturnKind::SameAsNext);
                    }
                }
            }

            kind.expect("start_checkpoint_index is checked to be below checkpoints_len; for loop above must have been executed at least once; it will either early return, or set the kind value to Some; qed")
        };

        match kind {
            ReturnKind::SameAsNext => Ok(Some(self.storage_at(address, key)?)),
            ReturnKind::OriginalAt => {
                Ok(Some(self.original_storage_at(address, key)?))
            }
        }
    }

    pub fn set_storage(
        &mut self, address: &Address, key: H256, value: H256, owner: Address,
    ) -> DbResult<()> {
        if self.storage_at(address, &key)? != value {
            self.require(address, false)?.set_storage(key, value, owner)
        }
        Ok(())
    }

    pub fn set_storage_layout(
        &mut self, address: &Address, layout: StorageLayout,
    ) -> DbResult<()> {
        self.require_or_from(
            address,
            false,
            || {
                OverlayAccount::new_contract(
                    address,
                    0.into(),
                    self.account_start_nonce,
                    false,
                )
            },
            |_| {},
        )?
        .set_storage_layout(layout);
        Ok(())
    }

    fn ensure_cached<F, U>(
        &self, address: &Address, require: RequireCache, f: F,
    ) -> DbResult<U>
    where F: Fn(Option<&OverlayAccount>) -> U {
        if let Some(ref mut maybe_acc) =
            self.cache.borrow_mut().get_mut(address)
        {
            if let Some(ref mut account) = maybe_acc.account {
                if Self::update_account_cache(require, account, &self.db) {
                    return Ok(f(Some(account)));
                } else {
                    return Err(DbErrorKind::IncompleteDatabase(
                        account.address().clone(),
                    )
                    .into());
                }
            }
        }

        let mut maybe_acc = self
            .db
            .get_account(address)?
            .map(|acc| OverlayAccount::new(address, acc, self.block_number));
        if let Some(ref mut account) = maybe_acc.as_mut() {
            if !Self::update_account_cache(require, account, &self.db) {
                return Err(DbErrorKind::IncompleteDatabase(
                    account.address().clone(),
                )
                .into());
            }
        }

        let r = f(maybe_acc.as_ref());
        self.insert_cache(address, AccountEntry::new_clean(maybe_acc));
        Ok(r)
    }

    fn require<'x>(
        &'x self, address: &Address, require_code: bool,
    ) -> DbResult<RefMut<'x, OverlayAccount>> {
        self.require_or_from(
            address,
            require_code,
            || {
                OverlayAccount::new_basic(
                    address,
                    0.into(),
                    self.account_start_nonce,
                )
            },
            |_| {},
        )
    }

    fn require_or_from<'x, F, G>(
        &'x self, address: &Address, require_code: bool, default: F,
        not_default: G,
    ) -> DbResult<RefMut<'x, OverlayAccount>>
    where
        F: FnOnce() -> OverlayAccount,
        G: FnOnce(&mut OverlayAccount),
    {
        let contains_key = self.cache.borrow().contains_key(address);
        if !contains_key {
            let account = self.db.get_account(address)?.map(|acc| {
                OverlayAccount::new(address, acc, self.block_number)
            });
            self.insert_cache(address, AccountEntry::new_clean(account));
        }
        self.note_cache(address);

        Ok(RefMut::map(self.cache.borrow_mut(), |c| {
            let entry = c
                .get_mut(address)
                .expect("entry known to exist in the cache; qed");

            match &mut entry.account {
                &mut Some(ref mut acc) => not_default(acc),
                slot => *slot = Some(default()),
            }

            // set the dirty flag after changing account data.
            entry.state = AccountState::Dirty;
            match entry.account {
                Some(ref mut account) => {
                    if require_code {
                        Self::update_account_cache(
                            RequireCache::Code,
                            account,
                            &self.db,
                        );
                    }
                    account
                }
                _ => panic!("Required account must always exist; qed"),
            }
        }))
    }

    pub fn clear(&mut self) {
        assert!(self.checkpoints.borrow().is_empty());
        assert!(self.staking_state_checkpoints.borrow().is_empty());
        self.cache.borrow_mut().clear();
        self.staking_state.interest_rate_per_block =
            self.db.get_annual_interest_rate().expect("no db error")
                / U256::from(BLOCKS_PER_YEAR);
        self.staking_state.accumulate_interest_rate =
            self.db.get_accumulate_interest_rate().expect("no db error");
        self.staking_state.total_issued_tokens =
            self.db.get_total_issued_tokens().expect("No db error");
        self.staking_state.total_staking_tokens =
            self.db.get_total_staking_tokens().expect("No db error");
        self.staking_state.total_storage_tokens =
            self.db.get_total_storage_tokens().expect("No db error");
    }
}
