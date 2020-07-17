// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod prefetcher;

use self::account_entry::{AccountEntry, AccountState};
use crate::{
    bytes::Bytes,
    consensus::debug::ComputeEpochDebugRecord,
    executive::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    hash::KECCAK_EMPTY,
    parameters::staking::*,
    statedb::{ErrorKind as DbErrorKind, Result as DbResult, StateDb},
    storage::StateRootWithAuxInfo,
    transaction_pool::SharedTransactionPool,
    vm_factory::VmFactory,
};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use primitives::{Account, EpochId, StorageKey, StorageLayout, StorageValue};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};

#[cfg(test)]
mod account_entry_tests;
#[cfg(test)]
mod state_tests;

mod account_entry;
mod substate;

pub use self::{
    account_entry::OverlayAccount,
    substate::{CallStackInfo, Substate},
};
use crate::evm::Spec;
use parking_lot::{MappedRwLockWriteGuard, RwLock, RwLockWriteGuard};

#[derive(Copy, Clone)]
enum RequireCache {
    None,
    CodeSize,
    Code,
    DepositList,
    VoteStakeList,
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
    // This field should never be read during tx execution. (Can be updated)
    total_storage_tokens: U256,
    // This is the interest rate per block.
    interest_rate_per_block: U256,
    // This is the accumulated interest rate.
    accumulate_interest_rate: U256,
}

pub struct State {
    db: StateDb,

    dirty_accounts_to_commit: Vec<(Address, AccountEntry)>,
    cache: RwLock<HashMap<Address, AccountEntry>>,
    staking_state_checkpoints: RwLock<Vec<StakingState>>,
    checkpoints: RwLock<Vec<HashMap<Address, Option<AccountEntry>>>>,
    account_start_nonce: U256,
    contract_start_nonce: U256,
    staking_state: StakingState,
    // This is the total number of blocks executed so far. It is the same as
    // the `number` entry in EVM Environment.
    block_number: u64,
    vm: VmFactory,
}

impl State {
    pub fn new(
        db: StateDb, vm: VmFactory, spec: &Spec, block_number: u64,
    ) -> Self {
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
        let account_start_nonce = U256::zero();
        let contract_start_nonce = if spec.no_empty {
            U256::one()
        } else {
            U256::zero()
        };
        State {
            db,
            cache: Default::default(),
            staking_state_checkpoints: Default::default(),
            checkpoints: Default::default(),
            account_start_nonce,
            contract_start_nonce,
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
            dirty_accounts_to_commit: Default::default(),
        }
    }

    pub fn contract_start_nonce(&self) -> U256 { self.contract_start_nonce }

    /// Increase block number and calculate the current secondary reward.
    pub fn increase_block_number(&mut self) -> U256 {
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
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

    /// Maintain `total_issued_tokens`.
    pub fn add_total_issued(&mut self, v: U256) {
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
        self.staking_state.total_issued_tokens += v;
    }

    /// Maintain `total_issued_tokens`. This is only used in the extremely
    /// unlikely case that there are a lot of partial invalid blocks.
    pub fn subtract_total_issued(&mut self, v: U256) {
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
        self.staking_state.total_issued_tokens -= v;
    }

    /// Get a VM factory that can execute on this state.
    pub fn vm_factory(&self) -> VmFactory { self.vm.clone() }

    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index.
    pub fn checkpoint(&mut self) -> usize {
        self.staking_state_checkpoints
            .get_mut()
            .push(self.staking_state.clone());
        let checkpoints = self.checkpoints.get_mut();
        let index = checkpoints.len();
        checkpoints.push(HashMap::new());
        index
    }

    /// Charges or refund storage collateral and update `total_storage_tokens`.
    pub fn settle_collateral_for_storage(
        &mut self, addr: &Address,
    ) -> DbResult<CollateralCheckResult> {
        let (inc, sub) =
            self.ensure_cached(addr, RequireCache::None, |acc| {
                acc.map_or((0, 0), |account| {
                    account.get_uncleared_storage_entries()
                })
            })?;
        if inc > 0 || sub > 0 {
            self.require_exists(addr, false)?
                .reset_uncleared_storage_entries();
        }

        if sub > 0 {
            let delta = U256::from(sub) * *COLLATERAL_PER_STORAGE_KEY;
            assert!(self.exists(addr)?);
            self.sub_collateral_for_storage(addr, &delta)?;
        }
        if inc > 0 {
            let delta = U256::from(inc) * *COLLATERAL_PER_STORAGE_KEY;
            if addr.is_contract_address() {
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
                let balance = self.balance(addr)?;
                // balance is not enough to cover storage incremental.
                if delta > balance {
                    return Ok(CollateralCheckResult::NotEnoughBalance {
                        required: delta,
                        got: balance,
                    });
                }
            }
            self.add_collateral_for_storage(addr, &delta)?;
        }
        Ok(CollateralCheckResult::Valid)
    }

    /// Collects the cache (`ownership_change` in `OverlayAccount`) of storage
    /// change and write to substate and
    /// `storage_released`/`storage_collateralized` in overlay account.
    // It is idempotent. But its execution is cost.
    pub fn collect_ownership_changed(
        &mut self, substate: &mut Substate,
    ) -> DbResult<CollateralCheckResult> {
        let mut collateral_for_storage_sub = HashMap::new();
        let mut collateral_for_storage_inc = HashMap::new();
        if let Some(checkpoint) = self.checkpoints.get_mut().last() {
            for address in checkpoint.keys() {
                if let Some(ref mut maybe_acc) = self
                    .cache
                    .get_mut()
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
        // TODO: the overlay account and substate seem store the same content,
        // to be remove one of them. But the current impl of suicide breaks
        // this consistency, it may be changed later.
        for (addr, sub) in &collateral_for_storage_sub {
            self.require_exists(&addr, false)?
                .add_unrefunded_storage_entries(*sub);
            *substate.storage_released.entry(*addr).or_insert(0) +=
                sub * BYTES_PER_STORAGE_KEY;
        }
        for (addr, inc) in &collateral_for_storage_inc {
            self.require_exists(&addr, false)?
                .add_unpaid_storage_entries(*inc);
            *substate.storage_collateralized.entry(*addr).or_insert(0) +=
                inc * BYTES_PER_STORAGE_KEY;
        }
        Ok(CollateralCheckResult::Valid)
    }

    pub fn collect_ownership_changed_and_settle(
        &mut self, original_sender: &Address, storage_limit: &U256,
        substate: &mut Substate,
    ) -> DbResult<CollateralCheckResult>
    {
        self.collect_ownership_changed(substate)?;

        let touched_addresses =
            if let Some(checkpoint) = self.checkpoints.get_mut().last() {
                checkpoint.keys().cloned().collect()
            } else {
                HashSet::new()
            };
        // No new addresses added to checkpoint in this for-loop.
        for address in touched_addresses.iter() {
            match self.settle_collateral_for_storage(address)? {
                CollateralCheckResult::Valid => {}
                res => return Ok(res),
            }
        }

        let collateral_for_storage =
            self.collateral_for_storage(original_sender)?;
        if collateral_for_storage > *storage_limit {
            Ok(CollateralCheckResult::ExceedStorageLimit {
                limit: *storage_limit,
                required: collateral_for_storage,
            })
        } else {
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
            self.staking_state_checkpoints.get_mut().pop();
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
                .get_mut()
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

    pub fn new_contract_with_admin(
        &mut self, contract: &Address, admin: &Address, balance: U256,
        nonce: U256,
    ) -> DbResult<()>
    {
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            contract,
            AccountEntry::new_dirty(Some(
                OverlayAccount::new_contract_with_admin(
                    contract, balance, nonce, admin,
                ),
            )),
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn new_contract(
        &mut self, contract: &Address, balance: U256, nonce: U256,
    ) -> DbResult<()> {
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            contract,
            AccountEntry::new_dirty(Some(OverlayAccount::new_contract(
                contract, balance, nonce,
            ))),
        );
        Ok(())
    }

    pub fn balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.balance())
        })
    }

    pub fn is_contract_with_code(&self, address: &Address) -> bool {
        if !address.is_contract_address() {
            return false;
        }
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| acc.code_hash() != KECCAK_EMPTY)
        })
        .unwrap_or(false)
    }

    fn maybe_address(address: &Address) -> Option<Address> {
        if address.is_zero() {
            None
        } else {
            Some(*address)
        }
    }

    pub fn sponsor_for_gas(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(None, |acc| {
                Self::maybe_address(&acc.sponsor_info().sponsor_for_gas)
            })
        })
    }

    pub fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(None, |acc| {
                Self::maybe_address(&acc.sponsor_info().sponsor_for_collateral)
            })
        })
    }

    pub fn set_sponsor_for_gas(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    ) -> DbResult<()>
    {
        if *sponsor != self.sponsor_for_gas(address)?.unwrap_or_default()
            || *sponsor_balance != self.sponsor_balance_for_gas(address)?
        {
            self.require_exists(address, false).map(|mut x| {
                x.set_sponsor_for_gas(sponsor, sponsor_balance, upper_bound)
            })
        } else {
            Ok(())
        }
    }

    pub fn set_sponsor_for_collateral(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
    ) -> DbResult<()> {
        if *sponsor != self.sponsor_for_collateral(address)?.unwrap_or_default()
            || *sponsor_balance
                != self.sponsor_balance_for_collateral(address)?
        {
            self.require_exists(address, false).map(|mut x| {
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
                    && acc.admin() == requester
                    && acc.admin() != admin
            })
        })? {
            self.require_exists(&contract_address, false)?
                .set_admin(requester, admin);
        }
        Ok(())
    }

    pub fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .sub_sponsor_balance_for_gas(by);
        }
        Ok(())
    }

    pub fn add_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .add_sponsor_balance_for_gas(by);
        }
        Ok(())
    }

    pub fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .sub_sponsor_balance_for_collateral(by);
        }
        Ok(())
    }

    pub fn add_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
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

        let mut account = self.require_exists(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            false,
        )?;
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
        let mut account = self.require_exists(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            false,
        )?;
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
        self.ensure_cached(address, RequireCache::VoteStakeList, |acc| {
            acc.map_or(U256::zero(), |acc| {
                acc.withdrawable_staking_balance(self.block_number)
            })
        })
    }

    pub fn deposit_list_length(&self, address: &Address) -> DbResult<usize> {
        self.ensure_cached(address, RequireCache::DepositList, |acc| {
            acc.map_or(0, |acc| acc.deposit_list().map_or(0, |l| l.len()))
        })
    }

    pub fn vote_stake_list_length(&self, address: &Address) -> DbResult<usize> {
        self.ensure_cached(address, RequireCache::VoteStakeList, |acc| {
            acc.map_or(0, |acc| acc.vote_stake_list().map_or(0, |l| l.len()))
        })
    }

    pub fn inc_nonce(&mut self, address: &Address) -> DbResult<()> {
        self.require_or_new_basic_account(address)
            .map(|mut x| x.inc_nonce())
    }

    pub fn set_nonce(
        &mut self, address: &Address, nonce: &U256,
    ) -> DbResult<()> {
        self.require_or_new_basic_account(address)
            .map(|mut x| x.set_nonce(nonce))
    }

    pub fn sub_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: &mut CleanupMode,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?.sub_balance(by);
        }

        if let CleanupMode::TrackTouched(ref mut set) = *cleanup_mode {
            if self.exists(address)? {
                set.insert(*address);
            }
        }
        Ok(())
    }

    pub fn add_balance(
        &mut self, address: &Address, by: &U256, cleanup_mode: CleanupMode,
    ) -> DbResult<()> {
        let exists = self.exists(address)?;
        if !address.is_valid_address() {
            // Sending to invalid addresses are not allowed. Note that this
            // check is required because at serialization we assume
            // only valid addresses.
            //
            // There are checks to forbid it at transact level.
            //
            // The logic here is intended for incorrect miner coin-base. In this
            // case, the mining reward get lost.
            warn!(
                "add_balance: address does not already exist and is not a valid address. {:?}",
                address
            );
            return Ok(());
        }
        if !by.is_zero()
            || (cleanup_mode == CleanupMode::ForceCreate && !exists)
        {
            self.require_or_new_basic_account(address)?.add_balance(by);
        }

        if let CleanupMode::TrackTouched(set) = cleanup_mode {
            if exists {
                set.insert(*address);
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
            self.require_exists(address, false)?
                .add_collateral_for_storage(by);
            self.staking_state.total_storage_tokens += *by;
        }
        Ok(())
    }

    pub fn sub_collateral_for_storage(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require_exists(address, false)?
                .sub_collateral_for_storage(by);
            self.staking_state.total_storage_tokens -= *by;
        }
        Ok(())
    }

    pub fn deposit(
        &mut self, address: &Address, amount: &U256,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            {
                let mut account = self.require_exists(address, false)?;
                account.cache_staking_info(
                    true,  /* cache_deposit_list */
                    false, /* cache_vote_list */
                    &self.db,
                )?;
                account.deposit(
                    *amount,
                    self.staking_state.accumulate_interest_rate,
                    self.block_number,
                );
            }
            self.staking_state.total_staking_tokens += *amount;
        }
        Ok(())
    }

    pub fn withdraw(
        &mut self, address: &Address, amount: &U256,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            let interest;
            {
                let mut account = self.require_exists(address, false)?;
                account.cache_staking_info(
                    true,  /* cache_deposit_list */
                    false, /* cache_vote_list */
                    &self.db,
                )?;
                interest = account.withdraw(
                    *amount,
                    self.staking_state.accumulate_interest_rate,
                );
            }
            // the interest will be put in balance.
            self.staking_state.total_issued_tokens += interest;
            self.staking_state.total_staking_tokens -= *amount;
        }
        Ok(())
    }

    pub fn vote_lock(
        &mut self, address: &Address, amount: &U256, unlock_block_number: u64,
    ) -> DbResult<()> {
        if !amount.is_zero() {
            let mut account = self.require_exists(address, false)?;
            account.cache_staking_info(
                false, /* cache_deposit_list */
                true,  /* cache_vote_list */
                &self.db,
            )?;
            account.vote_lock(*amount, unlock_block_number);
        }
        Ok(())
    }

    pub fn remove_expired_vote_stake_info(
        &mut self, address: &Address,
    ) -> DbResult<()> {
        let mut account = self.require_exists(address, false)?;
        account.cache_staking_info(
            false, /* cache_deposit_list */
            true,  /* cache_vote_list */
            &self.db,
        )?;
        account.remove_expired_vote_stake_info(self.block_number);
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
        drop(self.require_exists(address, false)?);
        Ok(())
    }

    fn needs_update(require: RequireCache, account: &OverlayAccount) -> bool {
        trace!("update_account_cache account={:?}", account);
        match require {
            RequireCache::None => false,
            RequireCache::Code | RequireCache::CodeSize => !account.is_cached(),
            RequireCache::DepositList => account.deposit_list().is_none(),
            RequireCache::VoteStakeList => account.vote_stake_list().is_none(),
        }
    }

    /// Load required account data from the databases. Returns whether the
    /// cache succeeds.
    fn update_account_cache(
        require: RequireCache, account: &mut OverlayAccount, db: &StateDb,
    ) -> bool {
        match require {
            RequireCache::None => true,
            RequireCache::Code | RequireCache::CodeSize => {
                account.cache_code(db).is_some()
            }
            RequireCache::DepositList => account
                .cache_staking_info(
                    true,  /* cache_deposit_list */
                    false, /* cache_vote_list */
                    db,
                )
                .is_ok(),
            RequireCache::VoteStakeList => account
                .cache_staking_info(
                    false, /* cache_deposit_list */
                    true,  /* cache_vote_list */
                    db,
                )
                .is_ok(),
        }
    }

    fn commit_staking_state(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()> {
        self.db.set_annual_interest_rate(
            &(self.staking_state.interest_rate_per_block
                * U256::from(BLOCKS_PER_YEAR)),
            debug_record.as_deref_mut(),
        )?;
        self.db.set_accumulate_interest_rate(
            &self.staking_state.accumulate_interest_rate,
            debug_record.as_deref_mut(),
        )?;
        self.db.set_total_issued_tokens(
            &self.staking_state.total_issued_tokens,
            debug_record.as_deref_mut(),
        )?;
        self.db.set_total_staking_tokens(
            &self.staking_state.total_staking_tokens,
            debug_record.as_deref_mut(),
        )?;
        self.db.set_total_storage_tokens(
            &self.staking_state.total_storage_tokens,
            debug_record,
        )?;
        Ok(())
    }

    /// Assume that only contract with zero `collateral_for_storage` will be
    /// killed.
    fn recycle_storage(
        &mut self, killed_addresses: Vec<Address>,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        for address in killed_addresses {
            self.db.delete(
                StorageKey::new_account_key(&address),
                debug_record.as_deref_mut(),
            )?;
            let storages_opt = self.db.delete_all(
                StorageKey::new_storage_root_key(&address),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete_all(
                StorageKey::new_code_root_key(&address),
                debug_record.as_deref_mut(),
            )?;
            if let Some(storage_key_value) = storages_opt {
                for (key, value) in storage_key_value {
                    if let StorageKey::StorageKey { .. } =
                        StorageKey::from_delta_mpt_key(&key[..])
                    {
                        let storage_value =
                            rlp::decode::<StorageValue>(value.as_ref())?;
                        let storage_owner =
                            storage_value.owner.as_ref().unwrap_or(&address);
                        assert!(self.exists(storage_owner)?);
                        self.sub_collateral_for_storage(
                            storage_owner,
                            &COLLATERAL_PER_STORAGE_KEY,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn precommit_make_dirty_accounts_list(&mut self) {
        if self.dirty_accounts_to_commit.is_empty() {
            let mut sorted_dirty_accounts = self
                .cache
                .get_mut()
                .drain()
                .filter_map(|(address, entry)| {
                    if entry.is_dirty() {
                        Some((address, entry))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            sorted_dirty_accounts.sort_by(|a, b| a.0.cmp(&b.0));
            self.dirty_accounts_to_commit = sorted_dirty_accounts;
        }
    }

    pub fn commit(
        &mut self, epoch_id: EpochId,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>
    {
        debug!("Commit epoch[{}]", epoch_id);
        assert!(self.checkpoints.get_mut().is_empty());
        assert!(self.staking_state_checkpoints.get_mut().is_empty());

        self.precommit_make_dirty_accounts_list();
        self.commit_staking_state(debug_record.as_deref_mut())?;

        let mut killed_addresses = Vec::new();
        for (address, entry) in self.dirty_accounts_to_commit.iter_mut() {
            entry.state = AccountState::Committed;
            match &mut entry.account {
                None => killed_addresses.push(*address),
                Some(account) => {
                    account
                        .commit(&mut self.db, debug_record.as_deref_mut())?;
                    self.db.set::<Account>(
                        StorageKey::new_account_key(address),
                        &account.as_account()?,
                        debug_record.as_deref_mut(),
                    )?;
                }
            }
        }
        self.recycle_storage(killed_addresses, debug_record)?;
        Ok(self.db.commit(epoch_id)?)
    }

    pub fn commit_and_notify(
        &mut self, epoch_id: EpochId, txpool: &SharedTransactionPool,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>
    {
        let result = self.commit(epoch_id, debug_record)?;

        debug!("Notify epoch[{}]", epoch_id);

        let mut accounts_for_txpool = vec![];
        for (_address, entry) in &self.dirty_accounts_to_commit {
            if let Some(account) = &entry.account {
                accounts_for_txpool.push(account.as_account()?);
            }
        }
        {
            // TODO: use channel to deliver the message.
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
        self.require_exists(address, false)?.init_code(code, owner);
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
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            address,
            AccountEntry::new_dirty(None),
        )
    }

    /// Return whether or not the address exists.
    pub fn try_load(&self, address: &Address) -> bool {
        if let Ok(true) =
            self.ensure_cached(address, RequireCache::None, |maybe| {
                maybe.is_some()
            })
        {
            // Try to load the code, but don't fail if there is no code.
            self.ensure_cached(address, RequireCache::Code, |_| ()).ok();
            true
        } else {
            false
        }
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
                .get_mut()
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

    pub fn storage_at(
        &self, address: &Address, key: &Vec<u8>,
    ) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| {
                account.storage_at(&self.db, key).unwrap_or(U256::zero())
            })
        })
    }

    /// Get the value of storage at a specific checkpoint.
    #[cfg(test)]
    pub fn checkpoint_storage_at(
        &self, start_checkpoint_index: usize, address: &Address, key: &Vec<u8>,
    ) -> DbResult<Option<U256>> {
        #[derive(Debug)]
        enum ReturnKind {
            OriginalAt,
            SameAsNext,
        }

        let kind = {
            let checkpoints = self.checkpoints.read();

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
                        } else if account.is_newly_created_contract() {
                            return Ok(Some(U256::zero()));
                        } else {
                            kind = Some(ReturnKind::OriginalAt);
                            break;
                        }
                    }
                    Some(Some(AccountEntry { account: None, .. })) => {
                        return Ok(Some(U256::zero()));
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
                match self.db.get::<StorageValue>(
                    StorageKey::new_storage_key(address, key.as_ref()),
                )? {
                    Some(storage_value) => Ok(Some(storage_value.value)),
                    None => Ok(Some(U256::zero())),
                }
            }
        }
    }

    pub fn set_storage(
        &mut self, address: &Address, key: Vec<u8>, value: U256, owner: Address,
    ) -> DbResult<()> {
        if self.storage_at(address, &key)? != value {
            self.require_exists(address, false)?
                .set_storage(key, value, owner)
        }
        Ok(())
    }

    pub fn set_storage_layout(
        &mut self, address: &Address, layout: StorageLayout,
    ) -> DbResult<()> {
        self.require_exists(address, false)?
            .set_storage_layout(layout);
        Ok(())
    }

    fn update_cache(
        cache: &mut HashMap<Address, AccountEntry>,
        checkpoints: &mut Vec<HashMap<Address, Option<AccountEntry>>>,
        address: &Address, account: AccountEntry,
    )
    {
        let is_dirty = account.is_dirty();
        let old_value = cache.insert(*address, account);
        if is_dirty {
            if let Some(ref mut checkpoint) = checkpoints.last_mut() {
                checkpoint.entry(*address).or_insert(old_value);
            }
        }
    }

    fn insert_cache_if_fresh_account(
        cache: &mut HashMap<Address, AccountEntry>, address: &Address,
        maybe_account: Option<OverlayAccount>,
    ) -> bool
    {
        if !cache.contains_key(address) {
            cache.insert(*address, AccountEntry::new_clean(maybe_account));
            true
        } else {
            false
        }
    }

    fn ensure_cached<F, U>(
        &self, address: &Address, require: RequireCache, f: F,
    ) -> DbResult<U>
    where F: Fn(Option<&OverlayAccount>) -> U {
        let needs_update =
            if let Some(maybe_acc) = self.cache.read().get(address) {
                if let Some(account) = &maybe_acc.account {
                    Self::needs_update(require, account)
                } else {
                    false
                }
            } else {
                false
            };

        if needs_update {
            if let Some(maybe_acc) = self.cache.write().get_mut(address) {
                if let Some(account) = &mut maybe_acc.account {
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
        }

        let maybe_acc = self
            .db
            .get_account(address)?
            .map(|acc| OverlayAccount::new(address, acc));
        let cache = &mut *self.cache.write();
        Self::insert_cache_if_fresh_account(cache, address, maybe_acc);

        let account = cache.get_mut(address).unwrap();
        if let Some(maybe_acc) = &mut account.account {
            if !Self::update_account_cache(require, maybe_acc, &self.db) {
                return Err(DbErrorKind::IncompleteDatabase(
                    maybe_acc.address().clone(),
                )
                .into());
            }
        }

        Ok(f(cache
            .get(address)
            .and_then(|entry| entry.account.as_ref())))
    }

    fn require_exists(
        &self, address: &Address, require_code: bool,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        fn no_account_is_an_error(
            address: &Address,
        ) -> DbResult<OverlayAccount> {
            bail!(DbErrorKind::IncompleteDatabase(*address));
        }
        self.require_or_set(address, require_code, no_account_is_an_error)
    }

    fn require_or_new_basic_account(
        &self, address: &Address,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        self.require_or_set(address, false, |address| {
            if address.is_valid_address() {
                // Note that it is possible to first send money to a pre-calculated contract
                // address and then deploy contracts. So we are going to *allow* sending to a contract
                // address and use new_basic() to create a *stub* there. Because the contract serialization
                // is a super-set of the normal address serialization, this should just work.
                Ok(OverlayAccount::new_basic(
                    address,
                    U256::zero(),
                    self.account_start_nonce.into(),
                ))
            } else {
                unreachable!(
                    "address does not already exist and is not an user account. {:?}",
                    address
                )
            }
        })
    }

    fn require_or_set<F>(
        &self, address: &Address, require_code: bool, default: F,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>>
    where F: FnOnce(&Address) -> DbResult<OverlayAccount> {
        let mut cache;
        if !self.cache.read().contains_key(address) {
            let account = self
                .db
                .get_account(address)?
                .map(|acc| OverlayAccount::new(address, acc));
            cache = self.cache.write();
            Self::insert_cache_if_fresh_account(&mut *cache, address, account);
        } else {
            cache = self.cache.write();
        };

        // Save the value before modification into the checkpoint.
        if let Some(ref mut checkpoint) = self.checkpoints.write().last_mut() {
            checkpoint.entry(*address).or_insert_with(|| {
                cache.get(address).map(AccountEntry::clone_dirty)
            });
        }

        let entry = (*cache)
            .get_mut(address)
            .expect("entry known to exist in the cache");

        // Set the dirty flag.
        entry.state = AccountState::Dirty;

        if entry.account.is_none() {
            entry.account = Some(default(address)?);
        }

        if require_code {
            if !Self::update_account_cache(
                RequireCache::Code,
                entry
                    .account
                    .as_mut()
                    .expect("Required account must exist."),
                &self.db,
            ) {
                bail!(DbErrorKind::IncompleteDatabase(*address));
            }
        }

        Ok(RwLockWriteGuard::map(cache, |c| {
            c.get_mut(address)
                .expect("Entry known to exist in the cache.")
                .account
                .as_mut()
                .expect("Required account must exist.")
        }))
    }

    pub fn clear(&mut self) {
        assert!(self.checkpoints.get_mut().is_empty());
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
        self.cache.get_mut().clear();
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
