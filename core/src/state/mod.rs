// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub use self::{
    account_entry::{OverlayAccount, COMMISSION_PRIVILEGE_SPECIAL_KEY},
    substate::{CallStackInfo, Substate},
};

use self::account_entry::{AccountEntry, AccountState};
use crate::{
    evm::Spec, hash::KECCAK_EMPTY, transaction_pool::SharedTransactionPool,
    vm::Error as vmError, vm_factory::VmFactory,
};
use cfx_bytes::Bytes;
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_parameters::{
    internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    staking::*,
};
use cfx_statedb::{
    ErrorKind as DbErrorKind, Result as DbResult, StateDbExt,
    StateDbGeneric as StateDb,
};
use cfx_storage::{utils::access_mode, StorageState, StorageStateTrait};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use parking_lot::{
    MappedRwLockWriteGuard, RwLock, RwLockUpgradableReadGuard, RwLockWriteGuard,
};
#[cfg(test)]
use primitives::storage::STORAGE_LAYOUT_REGULAR_V0;
use primitives::{
    Account, DepositList, EpochId, SkipInputCheck, SponsorInfo, StorageKey,
    StorageLayout, StorageValue, VoteStakeList,
};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};

mod account_entry;
#[cfg(test)]
mod account_entry_tests;
pub mod prefetcher;
#[cfg(test)]
mod state_tests;
mod substate;

#[derive(Copy, Clone)]
pub enum RequireCache {
    None,
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

impl CollateralCheckResult {
    pub fn into_vm_result(self) -> Result<(), vmError> {
        match self {
            CollateralCheckResult::ExceedStorageLimit { .. } => {
                Err(vmError::ExceedStorageLimit)
            }
            CollateralCheckResult::NotEnoughBalance { required, got } => {
                Err(vmError::NotEnoughBalanceForStorage { required, got })
            }
            CollateralCheckResult::Valid => Ok(()),
        }
    }
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

pub type State = StateGeneric<StorageState>;

pub struct StateGeneric<StateDbStorage: StorageStateTrait> {
    db: StateDb<StateDbStorage>,

    // Only created once for txpool notification.
    // Each element is an Ok(Account) for updated account, or Err(Address)
    // for deleted account.
    accounts_to_notify: Vec<Result<Account, Address>>,

    // Contains the changes to the states and some unchanged state entries.
    cache: RwLock<HashMap<Address, AccountEntry>>,
    // TODO: try not to make it special?
    staking_state: StakingState,

    // Checkpoint to the changes.
    staking_state_checkpoints: RwLock<Vec<StakingState>>,
    checkpoints: RwLock<Vec<HashMap<Address, Option<AccountEntry>>>>,

    // Environment variables.
    account_start_nonce: U256,
    contract_start_nonce: U256,
    // This is the total number of blocks executed so far. It is the same as
    // the `number` entry in EVM Environment.
    block_number: u64,
    vm: VmFactory,
}

impl<StateDbStorage: StorageStateTrait> StateGeneric<StateDbStorage> {
    pub fn new(
        db: StateDb<StateDbStorage>, vm: VmFactory, spec: &Spec,
        block_number: u64,
    ) -> DbResult<Self>
    {
        let annual_interest_rate = db.get_annual_interest_rate()?;
        let accumulate_interest_rate = db.get_accumulate_interest_rate()?;
        let total_issued_tokens = db.get_total_issued_tokens()?;
        let total_staking_tokens = db.get_total_staking_tokens()?;
        let total_storage_tokens = db.get_total_storage_tokens()?;

        let staking_state = if db.is_initialized()? {
            StakingState {
                total_issued_tokens,
                total_staking_tokens,
                total_storage_tokens,
                interest_rate_per_block: annual_interest_rate
                    / U256::from(BLOCKS_PER_YEAR),
                accumulate_interest_rate,
            }
        } else {
            // If db is not initialized, all the loaded value should be zero.
            assert!(
                annual_interest_rate.is_zero(),
                "annual_interest_rate is non-zero when db is un-init"
            );
            assert!(
                accumulate_interest_rate.is_zero(),
                "accumulate_interest_rate is non-zero when db is un-init"
            );
            assert!(
                total_issued_tokens.is_zero(),
                "total_issued_tokens is non-zero when db is un-init"
            );
            assert!(
                total_staking_tokens.is_zero(),
                "total_staking_tokens is non-zero when db is un-init"
            );
            assert!(
                total_storage_tokens.is_zero(),
                "total_storage_tokens is non-zero when db is un-init"
            );

            StakingState {
                total_issued_tokens: U256::default(),
                total_staking_tokens: U256::default(),
                total_storage_tokens: U256::default(),
                interest_rate_per_block: *INITIAL_INTEREST_RATE_PER_BLOCK,
                accumulate_interest_rate: *ACCUMULATED_INTEREST_RATE_SCALE,
            }
        };

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
        Ok(StateGeneric {
            db,
            cache: Default::default(),
            staking_state_checkpoints: Default::default(),
            checkpoints: Default::default(),
            account_start_nonce,
            contract_start_nonce,
            staking_state,
            block_number,
            vm,
            accounts_to_notify: Default::default(),
        })
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
    /// index. The checkpoint records any old value which is alive at the
    /// creation time of the checkpoint and updated after that and before
    /// the creation of the next checkpoint.
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
    pub fn settle_collateral_for_address(
        &mut self, addr: &Address, substate: &Substate,
    ) -> DbResult<CollateralCheckResult> {
        let (inc_collaterals, sub_collaterals) =
            substate.get_collateral_change(addr);
        let (inc, sub) = (
            *DRIPS_PER_STORAGE_COLLATERAL_UNIT * inc_collaterals,
            *DRIPS_PER_STORAGE_COLLATERAL_UNIT * sub_collaterals,
        );

        if !sub.is_zero() {
            self.sub_collateral_for_storage(addr, &sub)?;
        }
        if !inc.is_zero() {
            let balance = if addr.is_contract_address() {
                self.sponsor_balance_for_collateral(addr)?
            } else {
                self.balance(addr)?
            };
            // sponsor_balance is not enough to cover storage incremental.
            if inc > balance {
                return Ok(CollateralCheckResult::NotEnoughBalance {
                    required: inc,
                    got: balance,
                });
            }
            self.add_collateral_for_storage(addr, &inc)?;
        }
        Ok(CollateralCheckResult::Valid)
    }

    /// Collects the cache (`ownership_change` in `OverlayAccount`) of storage
    /// change and write to substate.
    // It is idempotent. But its execution is cost.
    pub fn collect_ownership_changed(
        &mut self, substate: &mut Substate,
    ) -> DbResult<()> {
        if let Some(checkpoint) = self.checkpoints.get_mut().last() {
            for address in checkpoint.keys() {
                if let Some(ref mut maybe_acc) = self
                    .cache
                    .get_mut()
                    .get_mut(address)
                    .filter(|x| x.is_dirty())
                {
                    if let Some(ref mut acc) = maybe_acc.account.as_mut() {
                        acc.commit_ownership_change(&self.db, substate)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Charge and refund all the storage collaterals.
    /// The suicided addresses are skimmed because their collateral have been
    /// checked out. This function should only be called in post-processing
    /// of a transaction.
    pub fn settle_collateral_for_all(
        &mut self, substate: &Substate,
    ) -> DbResult<CollateralCheckResult> {
        for address in substate.keys_for_collateral_changed().iter() {
            match self.settle_collateral_for_address(address, substate)? {
                CollateralCheckResult::Valid => {}
                res => return Ok(res),
            }
        }
        Ok(CollateralCheckResult::Valid)
    }

    pub fn check_storage_limit(
        &self, original_sender: &Address, storage_limit: &U256,
    ) -> DbResult<CollateralCheckResult> {
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

    // TODO: This function can only be called after VM execution. There are some
    // test cases breaks this assumption, which will be fixed in a separated PR.
    pub fn collect_and_settle_collateral(
        &mut self, original_sender: &Address, storage_limit: &U256,
        substate: &mut Substate,
    ) -> DbResult<CollateralCheckResult>
    {
        self.collect_ownership_changed(substate)?;
        let res = match self.settle_collateral_for_all(substate)? {
            CollateralCheckResult::Valid => {
                self.check_storage_limit(original_sender, storage_limit)?
            }
            res => res,
        };
        Ok(res)
    }

    /// Merge last checkpoint with previous.
    /// Caller should make sure the function
    /// `collect_ownership_changed()` was called before calling
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
        nonce: U256, storage_layout: Option<StorageLayout>,
    ) -> DbResult<()>
    {
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            contract,
            AccountEntry::new_dirty(Some(
                OverlayAccount::new_contract_with_admin(
                    contract,
                    balance,
                    nonce,
                    admin,
                    storage_layout,
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
                contract,
                balance,
                nonce,
                Some(STORAGE_LAYOUT_REGULAR_V0),
            ))),
        );
        Ok(())
    }

    pub fn balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.balance())
        })
    }

    pub fn is_contract_with_code(&self, address: &Address) -> DbResult<bool> {
        if !address.is_contract_address() {
            return Ok(false);
        }
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| acc.code_hash() != KECCAK_EMPTY)
        })
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
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(None, |acc| {
                Self::maybe_address(&acc.sponsor_info().sponsor_for_gas)
            })
        })
    }

    pub fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
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

    pub fn sponsor_info(
        &self, address: &Address,
    ) -> DbResult<Option<SponsorInfo>> {
        self.ensure_account_loaded(address, RequireCache::None, |maybe_acc| {
            maybe_acc.map(|acc| acc.sponsor_info().clone())
        })
    }

    pub fn sponsor_gas_bound(&self, address: &Address) -> DbResult<U256> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| acc.sponsor_info().sponsor_gas_bound)
        })
    }

    pub fn sponsor_balance_for_gas(&self, address: &Address) -> DbResult<U256> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| {
                acc.sponsor_info().sponsor_balance_for_gas
            })
        })
    }

    pub fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |acc| {
                acc.sponsor_info().sponsor_balance_for_collateral
            })
        })
    }

    pub fn set_admin(
        &mut self, contract_address: &Address, admin: &Address,
    ) -> DbResult<()> {
        self.require_exists(&contract_address, false)?
            .set_admin(admin);
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
        match self.ensure_account_loaded(
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
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.nonce())
        })
    }

    pub fn code_hash(&self, address: &Address) -> DbResult<Option<H256>> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.and_then(|acc| Some(acc.code_hash()))
        })
    }

    pub fn code_size(&self, address: &Address) -> DbResult<Option<usize>> {
        self.ensure_account_loaded(address, RequireCache::Code, |acc| {
            acc.and_then(|acc| acc.code_size())
        })
    }

    pub fn code_owner(&self, address: &Address) -> DbResult<Option<Address>> {
        self.ensure_account_loaded(address, RequireCache::Code, |acc| {
            acc.as_ref().map_or(None, |acc| acc.code_owner())
        })
    }

    pub fn code(&self, address: &Address) -> DbResult<Option<Arc<Bytes>>> {
        self.ensure_account_loaded(address, RequireCache::Code, |acc| {
            acc.as_ref().map_or(None, |acc| acc.code())
        })
    }

    pub fn staking_balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| *account.staking_balance())
        })
    }

    pub fn collateral_for_storage(&self, address: &Address) -> DbResult<U256> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(U256::zero(), |account| {
                *account.collateral_for_storage()
            })
        })
    }

    pub fn admin(&self, address: &Address) -> DbResult<Address> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(Address::zero(), |acc| *acc.admin())
        })
    }

    pub fn withdrawable_staking_balance(
        &self, address: &Address,
    ) -> DbResult<U256> {
        self.ensure_account_loaded(
            address,
            RequireCache::VoteStakeList,
            |acc| {
                acc.map_or(U256::zero(), |acc| {
                    acc.withdrawable_staking_balance(self.block_number)
                })
            },
        )
    }

    pub fn locked_staking_balance_at_block_number(
        &self, address: &Address, block_number: u64,
    ) -> DbResult<U256> {
        self.ensure_account_loaded(
            address,
            RequireCache::VoteStakeList,
            |acc| {
                acc.map_or(U256::zero(), |acc| {
                    acc.staking_balance()
                        - acc.withdrawable_staking_balance(block_number)
                })
            },
        )
    }

    pub fn deposit_list_length(&self, address: &Address) -> DbResult<usize> {
        self.ensure_account_loaded(address, RequireCache::DepositList, |acc| {
            acc.map_or(0, |acc| acc.deposit_list().map_or(0, |l| l.len()))
        })
    }

    pub fn vote_stake_list_length(&self, address: &Address) -> DbResult<usize> {
        self.ensure_account_loaded(
            address,
            RequireCache::VoteStakeList,
            |acc| {
                acc.map_or(0, |acc| {
                    acc.vote_stake_list().map_or(0, |l| l.len())
                })
            },
        )
    }

    pub fn clean_account(&mut self, address: &Address) -> DbResult<()> {
        *&mut *self.require_or_new_basic_account(address)? =
            OverlayAccount::from_loaded(address, Default::default());
        Ok(())
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
            debug!(
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
        let collateral = self.collateral_for_storage(address)?;
        let refundable = if by > &collateral { &collateral } else { by };
        let burnt = *by - *refundable;
        if !refundable.is_zero() {
            self.require_or_new_basic_account(address)?
                .sub_collateral_for_storage(refundable);
        }
        self.staking_state.total_storage_tokens -= *by;
        self.staking_state.total_issued_tokens -= burnt;

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
    ) -> DbResult<U256> {
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
            Ok(interest)
        } else {
            Ok(U256::zero())
        }
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
    pub fn touch(&mut self, address: &Address) -> DbResult<()> {
        drop(self.require_exists(address, false)?);
        Ok(())
    }

    fn needs_update(require: RequireCache, account: &OverlayAccount) -> bool {
        trace!("update_account_cache account={:?}", account);
        match require {
            RequireCache::None => false,
            RequireCache::Code => !account.is_code_loaded(),
            RequireCache::DepositList => account.deposit_list().is_none(),
            RequireCache::VoteStakeList => account.vote_stake_list().is_none(),
        }
    }

    /// Load required account data from the databases. Returns whether the
    /// cache succeeds.
    fn update_account_cache(
        require: RequireCache, account: &mut OverlayAccount,
        db: &StateDb<StateDbStorage>,
    ) -> DbResult<bool>
    {
        match require {
            RequireCache::None => Ok(true),
            RequireCache::Code => account.cache_code(db),
            RequireCache::DepositList => account.cache_staking_info(
                true,  /* cache_deposit_list */
                false, /* cache_vote_list */
                db,
            ),
            RequireCache::VoteStakeList => account.cache_staking_info(
                false, /* cache_deposit_list */
                true,  /* cache_vote_list */
                db,
            ),
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
    pub fn recycle_storage(
        &mut self, killed_addresses: Vec<Address>,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        // TODO: Think about kill_dust and collateral refund.
        for address in &killed_addresses {
            self.db.delete_all::<access_mode::Write>(
                StorageKey::new_storage_root_key(address),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete_all::<access_mode::Write>(
                StorageKey::new_code_root_key(address),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_account_key(address),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_deposit_list_key(address),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_vote_list_key(address),
                debug_record.as_deref_mut(),
            )?;
        }
        Ok(())
    }

    // It's guaranteed that the second call of this method is a no-op.
    pub fn compute_state_root(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo> {
        debug!("state.compute_state_root");

        assert!(self.checkpoints.get_mut().is_empty());
        assert!(self.staking_state_checkpoints.get_mut().is_empty());

        let mut sorted_dirty_accounts =
            self.cache.get_mut().drain().collect::<Vec<_>>();
        sorted_dirty_accounts.sort_by(|a, b| a.0.cmp(&b.0));

        let mut killed_addresses = Vec::new();
        for (address, entry) in sorted_dirty_accounts.iter_mut() {
            entry.state = AccountState::Committed;
            match &mut entry.account {
                None => {
                    killed_addresses.push(*address);
                    self.accounts_to_notify.push(Err(*address));
                }
                Some(account) => {
                    account.commit(
                        self,
                        address,
                        debug_record.as_deref_mut(),
                    )?;
                    self.accounts_to_notify.push(Ok(account.as_account()?));
                }
            }
        }
        self.recycle_storage(killed_addresses, debug_record.as_deref_mut())?;
        self.commit_staking_state(debug_record.as_deref_mut())?;
        self.db.compute_state_root(debug_record)
    }

    pub fn commit(
        &mut self, epoch_id: EpochId,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>
    {
        debug!("Commit epoch[{}]", epoch_id);
        self.compute_state_root(debug_record.as_deref_mut())?;
        Ok(self.db.commit(epoch_id, debug_record)?)
    }

    pub fn commit_and_notify(
        &mut self, epoch_id: EpochId, txpool: &SharedTransactionPool,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>
    {
        let result = self.commit(epoch_id, debug_record)?;

        debug!("Notify epoch[{}]", epoch_id);

        let mut accounts_for_txpool = vec![];
        for updated_or_deleted in &self.accounts_to_notify {
            // if the account is updated.
            if let Ok(account) = updated_or_deleted {
                accounts_for_txpool.push(account.clone());
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

    fn remove_whitelists_for_contract<AM: access_mode::AccessMode>(
        &mut self, address: &Address,
    ) -> DbResult<HashMap<Vec<u8>, Address>> {
        let mut storage_owner_map = HashMap::new();
        let key_values = self.db.delete_all::<AM>(
            StorageKey::new_storage_key(
                &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
                address.as_ref(),
            ),
            /* debug_record = */ None,
        )?;
        let mut sponsor_whitelist_control_address = self.require_exists(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            /* require_code = */ false,
        )?;
        for (key, value) in &key_values {
            if let StorageKey::StorageKey { storage_key, .. } =
                StorageKey::from_key_bytes::<SkipInputCheck>(&key[..])
            {
                let storage_value =
                    rlp::decode::<StorageValue>(value.as_ref())?;
                let storage_owner = storage_value.owner.unwrap_or_else(|| {
                    SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS.clone()
                });
                storage_owner_map.insert(storage_key.to_vec(), storage_owner);
            }
        }

        // Then scan storage changes in cache.
        for (key, _value) in
            sponsor_whitelist_control_address.storage_value_write_cache()
        {
            if key.starts_with(address.as_ref()) {
                if let Some(storage_owner) =
                    sponsor_whitelist_control_address
                        .original_ownership_at(&self.db, key)?
                {
                    storage_owner_map.insert(key.clone(), storage_owner);
                } else {
                    // The corresponding entry has been reset during transaction
                    // execution, so we do not need to handle it now.
                    storage_owner_map.remove(key);
                }
            }
        }
        if !AM::is_read_only() {
            // Note removal of all keys in storage_value_read_cache and
            // storage_value_write_cache.
            for (key, _storage_owner) in &storage_owner_map {
                debug!("delete sponsor key {:?}", key);
                sponsor_whitelist_control_address.set_storage(
                    key.clone(),
                    U256::zero(),
                    /* owner doesn't matter for 0 value */
                    Address::zero(),
                );
            }
        }

        Ok(storage_owner_map)
    }

    pub fn record_storage_and_whitelist_entries_release(
        &mut self, address: &Address, substate: &mut Substate,
    ) -> DbResult<()> {
        self.remove_whitelists_for_contract::<access_mode::Write>(address)?;

        // Process collateral for removed storage.
        // TODO: try to do it in a better way, e.g. first log the deletion
        //  somewhere then apply the collateral change.
        {
            let mut sponsor_whitelist_control_address = self.require_exists(
                &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
                /* require_code = */ false,
            )?;
            sponsor_whitelist_control_address
                .commit_ownership_change(&self.db, substate)?;
        }

        let account_cache_read_guard = self.cache.read();
        let maybe_account = account_cache_read_guard
            .get(address)
            .and_then(|acc| acc.account.as_ref());

        let storage_key_value = self.db.delete_all::<access_mode::Read>(
            StorageKey::new_storage_root_key(address),
            None,
        )?;
        for (key, value) in &storage_key_value {
            if let StorageKey::StorageKey { storage_key, .. } =
                StorageKey::from_key_bytes::<SkipInputCheck>(&key[..])
            {
                // Check if the key has been touched. We use the local
                // information to find out if collateral refund is necessary
                // for touched keys.
                if maybe_account.map_or(true, |acc| {
                    acc.storage_value_write_cache().get(storage_key).is_none()
                }) {
                    let storage_value =
                        rlp::decode::<StorageValue>(value.as_ref())?;
                    let storage_owner =
                        storage_value.owner.as_ref().unwrap_or(address);
                    substate.record_storage_release(
                        storage_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                }
            }
        }

        if let Some(acc) = maybe_account {
            // The current value isn't important because it will be deleted.
            for (key, _value) in acc.storage_value_write_cache() {
                if let Some(storage_owner) =
                    acc.original_ownership_at(&self.db, key)?
                {
                    substate.record_storage_release(
                        &storage_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                }
            }
        }
        Ok(())
    }

    pub fn remove_contract(&mut self, address: &Address) -> DbResult<()> {
        let removed_whitelist =
            self.remove_whitelists_for_contract::<access_mode::Write>(address)?;
        if !removed_whitelist.is_empty() {
            error!(
                "removed_whitelist here should be empty unless in unit tests."
            );
        }
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            address,
            AccountEntry::new_dirty(None),
        );

        Ok(())
    }

    /// Return whether or not the address exists.
    pub fn try_load(&self, address: &Address) -> bool {
        if self
            .ensure_account_loaded(address, RequireCache::None, |maybe| {
                maybe.is_some()
            })
            .unwrap()
        {
            // Try to load the code, but don't fail if there is no code.
            self.ensure_account_loaded(address, RequireCache::Code, |_| ())
                .unwrap();
            true
        } else {
            false
        }
    }

    pub fn exists(&self, address: &Address) -> DbResult<bool> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.is_some()
        })
    }

    pub fn exists_and_not_null(&self, address: &Address) -> DbResult<bool> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(false, |acc| !acc.is_null())
        })
    }

    #[allow(unused)]
    pub fn exists_and_has_code_or_nonce(
        &self, address: &Address,
    ) -> DbResult<bool> {
        self.ensure_account_loaded(address, RequireCache::Code, |acc| {
            acc.map_or(false, |acc| {
                acc.code_hash() != KECCAK_EMPTY
                    || *acc.nonce() != self.account_start_nonce
            })
        })
    }

    // FIXME: rewrite this method before enable it for the first time, because
    //  there have been changes to kill_account and collateral processing.
    #[allow(unused)]
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
            // TODO: The kill_garbage relies on the info in contract kill
            // process. So it is processed later than contract kill. But we do
            // not want to kill some contract again here. We must discuss it
            // before enable kill_garbage.
            unimplemented!()
        }

        Ok(())
    }

    pub fn storage_at(&self, address: &Address, key: &[u8]) -> DbResult<U256> {
        self.ensure_account_loaded(address, RequireCache::None, |acc| {
            acc.map_or(Ok(U256::zero()), |account| {
                account.storage_at(&self.db, key)
            })
        })?
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

    pub fn ensure_account_loaded<F, U>(
        &self, address: &Address, require: RequireCache, f: F,
    ) -> DbResult<U>
    where F: Fn(Option<&OverlayAccount>) -> U {
        // Return immediately when there is no need to have db operation.
        if let Some(maybe_acc) = self.cache.read().get(address) {
            if let Some(account) = &maybe_acc.account {
                let needs_update = Self::needs_update(require, account);
                if !needs_update {
                    return Ok(f(Some(account)));
                }
            } else {
                return Ok(f(None));
            }
        }

        let mut cache_write_lock = {
            let upgradable_lock = self.cache.upgradable_read();
            if upgradable_lock.contains_key(address) {
                // TODO: the account can be updated here if the relevant methods
                //  to update account can run with &OverlayAccount.
                RwLockUpgradableReadGuard::upgrade(upgradable_lock)
            } else {
                // Load the account from db.
                let mut maybe_loaded_acc = self
                    .db
                    .get_account(address)?
                    .map(|acc| OverlayAccount::from_loaded(address, acc));
                if let Some(account) = &mut maybe_loaded_acc {
                    Self::update_account_cache(require, account, &self.db)?;
                }
                let mut cache_write_lock =
                    RwLockUpgradableReadGuard::upgrade(upgradable_lock);
                Self::insert_cache_if_fresh_account(
                    &mut *cache_write_lock,
                    address,
                    maybe_loaded_acc,
                );

                cache_write_lock
            }
        };

        let cache = &mut *cache_write_lock;
        let account = cache.get_mut(address).unwrap();
        if let Some(maybe_acc) = &mut account.account {
            if !Self::update_account_cache(require, maybe_acc, &self.db)? {
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
                    None,
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
                .map(|acc| OverlayAccount::from_loaded(address, acc));
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
            )? {
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

    pub fn clear_test_only(&mut self) {
        assert!(self.checkpoints.get_mut().is_empty());
        assert!(self.staking_state_checkpoints.get_mut().is_empty());
        self.cache.get_mut().clear();
        self.staking_state.interest_rate_per_block =
            self.db.get_annual_interest_rate().expect("no db error")
                / U256::from(BLOCKS_PER_YEAR);
        self.staking_state.accumulate_interest_rate =
            self.db.get_accumulate_interest_rate().expect("no db error");
        self.staking_state.total_issued_tokens =
            self.db.get_total_issued_tokens().expect("no db error");
        self.staking_state.total_staking_tokens =
            self.db.get_total_staking_tokens().expect("no db error");
        self.staking_state.total_storage_tokens =
            self.db.get_total_storage_tokens().expect("no db error");
    }
}

/// Methods that are intentionally kept private because the fields may not have
/// been loaded from db.
trait AccountEntryProtectedMethods {
    fn deposit_list(&self) -> Option<&DepositList>;
    fn vote_stake_list(&self) -> Option<&VoteStakeList>;
    fn code_size(&self) -> Option<usize>;
    fn code(&self) -> Option<Arc<Bytes>>;
    fn code_owner(&self) -> Option<Address>;
}
