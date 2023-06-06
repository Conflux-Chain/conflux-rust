// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};

use parking_lot::RwLock;

use cfx_bytes::Bytes;
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_parameters::{
    internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    staking::*,
};
use cfx_state::CleanupMode;
use cfx_statedb::{Result as DbResult, StateDbExt, StateDbGeneric as StateDb};
use cfx_storage::utils::access_mode;
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, Space, U256};
#[cfg(test)]
use primitives::storage::STORAGE_LAYOUT_REGULAR_V0;
use primitives::{
    Account, DepositList, EpochId, SkipInputCheck, StorageKey,
    StorageKeyWithSpace, StorageLayout, StorageValue, VoteStakeList,
};

pub use account_proxy::{
    collateral::settle_collateral_for_all,
    pos::{distribute_pos_interest, update_pos_status},
    staking::initialize_or_update_dao_voted_params,
};

use crate::{
    observer::StateTracer, transaction_pool::SharedTransactionPool, vm::Spec,
};

use self::account_entry::{AccountEntry, AccountState};
pub use self::{
    account_entry::{OverlayAccount, COMMISSION_PRIVILEGE_SPECIAL_KEY},
    substate::{cleanup_mode, CallStackInfo, Substate},
};

mod account_entry;
#[cfg(test)]
mod account_entry_tests;
mod account_proxy;
mod db_access;
pub mod prefetcher;
#[cfg(test)]
mod state_tests;
mod substate;
mod trace;

#[derive(Copy, Clone)]
pub enum RequireCache {
    None,
    Code,
    DepositList,
    VoteStakeList,
}

use cfx_statedb::{for_all_global_param_keys, global_params};

mod global_stat;
use global_stat::GlobalStat;

pub struct State {
    db: StateDb,

    // Only created once for txpool notification.
    // Each element is an Ok(Account) for updated account, or
    // Err(AddressWithSpace) for deleted account.
    accounts_to_notify: Vec<Result<Account, AddressWithSpace>>,

    // Contains the changes to the states and some unchanged state entries.
    cache: RwLock<HashMap<AddressWithSpace, AccountEntry>>,
    // TODO: try not to make it special?
    global_stat: GlobalStat,

    // Checkpoint to the changes.
    global_stat_checkpoints: RwLock<Vec<GlobalStat>>,
    checkpoints: RwLock<Vec<HashMap<AddressWithSpace, Option<AccountEntry>>>>,
}

impl State {
    pub fn record_storage_and_whitelist_entries_release(
        &mut self, address: &Address, substate: &mut Substate,
    ) -> DbResult<()> {
        self.remove_whitelists_for_contract::<access_mode::Write>(address)?;

        // Process collateral for removed storage.
        // TODO: try to do it in a better way, e.g. first log the deletion
        //  somewhere then apply the collateral change.
        {
            let mut sponsor_whitelist_control_address = self.require_exists(
                &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS.with_native_space(),
                /* require_code = */ false,
            )?;
            sponsor_whitelist_control_address
                .commit_ownership_change(&self.db, substate)?;
        }

        let account_cache_read_guard = self.cache.read();
        let maybe_account = account_cache_read_guard
            .get(&address.with_native_space())
            .and_then(|acc| acc.account.as_ref());

        let storage_key_value = self.db.delete_all::<access_mode::Read>(
            StorageKey::new_storage_root_key(address).with_native_space(),
            None,
        )?;
        for (key, value) in &storage_key_value {
            if let StorageKeyWithSpace {
                key: StorageKey::StorageKey { storage_key, .. },
                space,
            } =
                StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key[..])
            {
                assert_eq!(space, Space::Native);
                // Check if the key has been touched. We use the local
                // information to find out if collateral refund is necessary
                // for touched keys.
                if maybe_account.map_or(true, |acc| {
                    acc.storage_value_write_cache().get(storage_key).is_none()
                }) {
                    let storage_value =
                        rlp::decode::<StorageValue>(value.as_ref())?;
                    // Must native space
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

    // It's guaranteed that the second call of this method is a no-op.
    pub fn compute_state_root(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo> {
        debug!("state.compute_state_root");

        assert!(self.checkpoints.get_mut().is_empty());
        assert!(self.global_stat_checkpoints.get_mut().is_empty());

        let mut sorted_dirty_accounts =
            self.cache.get_mut().drain().collect::<Vec<_>>();
        sorted_dirty_accounts.sort_by(|a, b| a.0.cmp(&b.0));

        let mut killed_addresses = Vec::new();
        for (address, entry) in sorted_dirty_accounts.iter_mut() {
            entry.state = AccountState::Committed;
            match &mut entry.account {
                None => {}
                Some(account) if account.removed_without_update() => {
                    killed_addresses.push(*address);
                    self.accounts_to_notify.push(Err(*address));
                }
                Some(account) => {
                    account.commit(
                        self,
                        address,
                        debug_record.as_deref_mut(),
                    )?;
                    self.accounts_to_notify.push(Ok(account.as_account()));
                }
            }
        }
        self.recycle_storage(killed_addresses, debug_record.as_deref_mut())?;
        self.commit_world_statistics(debug_record.as_deref_mut())?;
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
}

impl State {
    pub fn new_contract_with_admin(
        &mut self, contract: &AddressWithSpace, admin: &Address, balance: U256,
        storage_layout: Option<StorageLayout>, cip107: bool,
    ) -> DbResult<()>
    {
        assert!(contract.space == Space::Native || admin.is_zero());
        // Check if the new contract is deployed on a killed contract in the
        // same block.
        let invalidated_storage = self
            .read_account(contract)?
            .map_or(false, |overlay| overlay.invalidated_storage());
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            contract,
            AccountEntry::new_dirty(Some(
                OverlayAccount::new_contract_with_admin(
                    contract,
                    balance,
                    admin,
                    invalidated_storage,
                    storage_layout,
                    cip107,
                ),
            )),
        );
        Ok(())
    }

    pub fn remove_contract(
        &mut self, address: &AddressWithSpace,
    ) -> DbResult<()> {
        if address.space == Space::Native {
            let removed_whitelist = self
                .remove_whitelists_for_contract::<access_mode::Write>(
                    &address.address,
                )?;

            if !removed_whitelist.is_empty() {
                error!(
                "removed_whitelist here should be empty unless in unit tests."
            );
            }
        }

        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            address,
            AccountEntry::new_dirty(Some(OverlayAccount::new_removed(address))),
        );

        Ok(())
    }

    pub fn read_vote(&self, _address: &Address) -> DbResult<Vec<u8>> { todo!() }
}

impl State {
    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index. The checkpoint records any old value which is alive at the
    /// creation time of the checkpoint and updated after that and before
    /// the creation of the next checkpoint.
    pub fn checkpoint(&mut self) -> usize {
        self.global_stat_checkpoints
            .get_mut()
            .push(self.global_stat.clone());
        let checkpoints = self.checkpoints.get_mut();
        let index = checkpoints.len();
        checkpoints.push(HashMap::new());
        index
    }

    /// Merge last checkpoint with previous.
    /// Caller should make sure the function
    /// `collect_ownership_changed()` was called before calling
    /// this function.
    pub fn discard_checkpoint(&mut self) {
        // merge with previous checkpoint
        let last = self.checkpoints.get_mut().pop();
        if let Some(mut checkpoint) = last {
            self.global_stat_checkpoints.get_mut().pop();
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
            self.global_stat = self
                .global_stat_checkpoints
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

    #[cfg(any(test, feature = "testonly_code"))]
    pub fn clear(&mut self) {
        assert!(self.checkpoints.get_mut().is_empty());
        assert!(self.global_stat_checkpoints.get_mut().is_empty());
        self.cache.get_mut().clear();
        self.global_stat = GlobalStat::loaded(&self.db).expect("no db error");
    }
}

impl State {
    pub fn new(db: StateDb) -> DbResult<Self> {
        let initialized = db.is_initialized()?;

        let world_stat = if initialized {
            GlobalStat::loaded(&db)?
        } else {
            // If db is not initialized, all the loaded value should be zero.
            fn assert_zero_global_params<T: GlobalParamKey>(
                db: &StateDb,
            ) -> DbResult<()> {
                assert!(
                    db.get_global_param::<T>()?.is_zero(),
                    "{:x?} is non-zero when db is un-init",
                    T::STORAGE_KEY
                );
                Ok(())
            }
            use global_params::*;
            for_all_global_param_keys! {
                assert_zero_global_params::<Key>(&db)?;
            }
            GlobalStat::new()
        };

        Ok(State {
            db,
            cache: Default::default(),
            global_stat_checkpoints: Default::default(),
            checkpoints: Default::default(),
            global_stat: world_stat,
            accounts_to_notify: Default::default(),
        })
    }

    pub fn add_pos_interest(
        &mut self, address: &Address, interest: &U256,
        cleanup_mode: CleanupMode,
    ) -> DbResult<()>
    {
        let address = address.with_native_space();
        self.add_total_issued(*interest);
        self.add_balance(&address, interest, cleanup_mode)?;
        self.require_or_new_basic_account(&address)?
            .record_interest_receive(interest);
        Ok(())
    }

    #[cfg(test)]
    pub fn new_contract(
        &mut self, contract: &AddressWithSpace, balance: U256,
    ) -> DbResult<()> {
        let invalidated_storage = self
            .read_account(contract)?
            .map_or(false, |acc| acc.invalidated_storage());
        Self::update_cache(
            self.cache.get_mut(),
            self.checkpoints.get_mut(),
            contract,
            AccountEntry::new_dirty(Some(OverlayAccount::new_contract(
                &contract.address,
                balance,
                invalidated_storage,
                Some(STORAGE_LAYOUT_REGULAR_V0),
            ))),
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn new_contract_with_code(
        &mut self, contract: &AddressWithSpace, balance: U256,
    ) -> DbResult<()> {
        self.new_contract(contract, balance)?;
        self.init_code(&contract, vec![0x12, 0x34], Address::zero())?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn touch(&mut self, address: &AddressWithSpace) -> DbResult<()> {
        drop(self.require_exists(address, false)?);
        Ok(())
    }

    /// Load required account data from the databases. Returns whether the
    /// cache succeeds.
    fn update_account_cache(
        require: RequireCache, account: &mut OverlayAccount, db: &StateDb,
    ) -> DbResult<bool> {
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

    fn commit_world_statistics(
        &mut self, debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()> {
        self.global_stat.commit(&mut self.db, debug_record)
    }

    /// Assume that only contract with zero `collateral_for_storage` will be
    /// killed.
    pub fn recycle_storage(
        &mut self, killed_addresses: Vec<AddressWithSpace>,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        // TODO: Think about kill_dust and collateral refund.
        for address in &killed_addresses {
            self.db.delete_all::<access_mode::Write>(
                StorageKey::new_storage_root_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete_all::<access_mode::Write>(
                StorageKey::new_code_root_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_account_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_deposit_list_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_vote_list_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
        }
        Ok(())
    }

    // FIXME: this should be part of the statetrait however transaction pool
    // creates circular dep.  if it proves impossible to break the loop we
    // use associated types for the tx pool.
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

    fn remove_whitelists_for_contract<AM: access_mode::AccessMode>(
        &mut self, address: &Address,
    ) -> DbResult<HashMap<Vec<u8>, Address>> {
        let mut storage_owner_map = HashMap::new();
        let key_values = self.db.delete_all::<AM>(
            StorageKey::new_storage_key(
                &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
                address.as_ref(),
            )
            .with_native_space(),
            /* debug_record = */ None,
        )?;
        let mut sponsor_whitelist_control_address = self.require_exists(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS.with_native_space(),
            /* require_code = */ false,
        )?;
        for (key, value) in &key_values {
            if let StorageKeyWithSpace {
                key: StorageKey::StorageKey { storage_key, .. },
                space,
            } =
                StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key[..])
            {
                assert_eq!(space, Space::Native);
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

    /// Get the value of storage at a specific checkpoint.
    #[cfg(test)]
    pub fn checkpoint_storage_at(
        &self, start_checkpoint_index: usize, address: &AddressWithSpace,
        key: &Vec<u8>,
    ) -> DbResult<Option<U256>>
    {
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
                    StorageKey::new_storage_key(&address.address, key.as_ref())
                        .with_space(address.space),
                )? {
                    Some(storage_value) => Ok(Some(storage_value.value)),
                    None => Ok(Some(U256::zero())),
                }
            }
        }
    }

    fn update_cache(
        cache: &mut HashMap<AddressWithSpace, AccountEntry>,
        checkpoints: &mut Vec<HashMap<AddressWithSpace, Option<AccountEntry>>>,
        address: &AddressWithSpace, account: AccountEntry,
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
        cache: &mut HashMap<AddressWithSpace, AccountEntry>,
        address: &AddressWithSpace, maybe_account: Option<OverlayAccount>,
    ) -> bool
    {
        if !cache.contains_key(address) {
            cache.insert(*address, AccountEntry::new_clean(maybe_account));
            true
        } else {
            false
        }
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
