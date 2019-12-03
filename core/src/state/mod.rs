// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use self::account_entry::{
    AccountEntry, AccountState, OverlayAccount, StorageValue,
};
use crate::{
    bytes::Bytes,
    hash::KECCAK_EMPTY,
    parameters::consensus_internal::RENTAL_PRICE_PER_STORAGE_KEY,
    statedb::{ErrorKind as DbErrorKind, Result as DbResult, StateDb},
    storage::StateRootWithAuxInfo,
    transaction_pool::SharedTransactionPool,
    vm_factory::VmFactory,
};
use cfx_types::{Address, H256, U256};
use primitives::{Account, EpochId, StorageKey};
use std::{
    cell::{RefCell, RefMut},
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};

mod account_entry;
mod substate;

pub use self::substate::Substate;

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
    TrackTouched(&'a mut HashSet<Address>),
}

pub struct State<'a> {
    db: StateDb<'a>,

    cache: RefCell<HashMap<Address, AccountEntry>>,
    checkpoints: RefCell<Vec<HashMap<Address, Option<AccountEntry>>>>,
    account_start_nonce: U256,
    total_tokens: U256,
    total_bank_tokens: U256,
    total_storage_tokens: U256,
    interest_rate: U256,
    accumulate_interest_rate: U256,
    vm: VmFactory,
}

impl<'a> State<'a> {
    pub fn new(
        db: StateDb<'a>, account_start_nonce: U256, vm: VmFactory,
    ) -> Self {
        let interest_rate = db.get_interest_rate().expect("no db error");
        let accumulate_interest_rate =
            db.get_accumulate_interest_rate().expect("no db error");
        let total_tokens = db.get_total_tokens().expect("No db error");
        let total_bank_tokens =
            db.get_total_bank_tokens().expect("No db error");
        let total_storage_tokens =
            db.get_total_storage_tokens().expect("No db error");
        State {
            db,
            cache: RefCell::new(HashMap::new()),
            checkpoints: RefCell::new(Vec::new()),
            account_start_nonce,
            total_tokens,
            total_bank_tokens,
            total_storage_tokens,
            interest_rate,
            accumulate_interest_rate,
            vm,
        }
    }

    /// Get a VM factory that can execute on this state.
    pub fn vm_factory(&self) -> VmFactory { self.vm.clone() }

    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index.
    pub fn checkpoint(&mut self) -> usize {
        let checkpoints = self.checkpoints.get_mut();
        let index = checkpoints.len();
        checkpoints.push(HashMap::new());
        index
    }

    /// return true if all accounts has enough storage balance.
    pub fn check_storage_balance(&mut self) -> bool {
        let mut storage_balance_sub = HashMap::new();
        let mut storage_balance_inc = HashMap::new();
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
                                *storage_balance_inc
                                    .entry(addr)
                                    .or_insert(0) += inc;
                            }
                            if sub > 0 {
                                *storage_balance_sub
                                    .entry(addr)
                                    .or_insert(0) += sub;
                            }
                        }
                    }
                }
            }
        }
        for (addr, sub) in storage_balance_sub {
            let delta =
                U256::from(sub) * U256::from(RENTAL_PRICE_PER_STORAGE_KEY);
            self.sub_storage_balance(&addr, &delta)
                .expect("no db error");
        }
        for (addr, inc) in storage_balance_inc {
            let delta =
                U256::from(inc) * U256::from(RENTAL_PRICE_PER_STORAGE_KEY);
            let bank_balance = self.bank_balance(&addr).expect("no db error");
            let storage_balance =
                self.storage_balance(&addr).expect("no db error");
            if storage_balance + delta > bank_balance {
                return false;
            }
            self.add_storage_balance(&addr, &delta)
                .expect("no db error");
        }
        true
    }

    /// Merge last checkpoint with previous.
    pub fn discard_checkpoint(&mut self) {
        // merge with previous checkpoint
        let last = self.checkpoints.get_mut().pop();
        if let Some(mut checkpoint) = last {
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
        self.ensure_cached(address, RequireCache::None, true, |acc| {
            acc.map_or(U256::zero(), |account| *account.balance())
        })
    }

    pub fn nonce(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, true, |acc| {
            acc.map_or(U256::zero(), |account| *account.nonce())
        })
    }

    pub fn code_hash(&self, address: &Address) -> DbResult<Option<H256>> {
        self.ensure_cached(address, RequireCache::None, true, |acc| {
            acc.and_then(|acc| Some(acc.code_hash()))
        })
    }

    pub fn code_size(&self, address: &Address) -> DbResult<Option<usize>> {
        self.ensure_cached(address, RequireCache::CodeSize, true, |acc| {
            acc.and_then(|acc| acc.code_size())
        })
    }

    pub fn code(&self, address: &Address) -> DbResult<Option<Arc<Bytes>>> {
        self.ensure_cached(address, RequireCache::Code, true, |acc| {
            acc.as_ref().map_or(None, |acc| acc.code())
        })
    }

    pub fn bank_balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, true, |acc| {
            acc.map_or(U256::zero(), |account| *account.bank_balance())
        })
    }

    pub fn storage_balance(&self, address: &Address) -> DbResult<U256> {
        self.ensure_cached(address, RequireCache::None, true, |acc| {
            acc.map_or(U256::zero(), |account| *account.storage_balance())
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
                self.touch(address)?;
            }
        }
        Ok(())
    }

    /// Caller should make sure that bank_balance for this account is sufficient
    /// enough.
    pub fn add_storage_balance(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?.add_storage_balance(by);
            self.total_storage_tokens += *by;
        }
        Ok(())
    }

    pub fn sub_storage_balance(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?.sub_storage_balance(by);
            self.total_storage_tokens -= *by;
        }
        Ok(())
    }

    pub fn deposit(&mut self, address: &Address, by: &U256) -> DbResult<()> {
        // TODO: check account type, only basic account can deposit
        if !by.is_zero() {
            self.require(address, false)?.deposit(by);
            self.total_bank_tokens += *by;
        }
        Ok(())
    }

    pub fn withdraw(&mut self, address: &Address, by: &U256) -> DbResult<()> {
        if !by.is_zero() {
            self.require(address, false)?.withdraw(by);
            self.total_bank_tokens -= *by;
        }
        Ok(())
    }

    pub fn interest_rate(&self) -> &U256 { &self.interest_rate }

    pub fn set_interest_rate(&mut self, new_interest_rate: U256) {
        self.interest_rate = new_interest_rate;
    }

    pub fn accumulate_interest_rate(&self) -> &U256 {
        &self.accumulate_interest_rate
    }

    pub fn set_accumulate_interest_rate(
        &mut self, accumulate_interest_rate: U256,
    ) {
        self.accumulate_interest_rate = accumulate_interest_rate;
    }

    pub fn total_tokens(&self) -> &U256 { &self.total_tokens }

    pub fn set_total_tokens(&mut self, total_tokens: U256) {
        self.total_tokens = total_tokens;
    }

    pub fn total_bank_tokens(&self) -> &U256 { &self.total_bank_tokens }

    pub fn total_storage_tokens(&self) -> &U256 { &self.total_storage_tokens }

    fn touch(&mut self, address: &Address) -> DbResult<()> {
        self.require(address, false)?;
        Ok(())
    }

    /// Load required account data from the databases. Returns whether the
    /// cache succeeds.
    fn update_account_cache(
        require: RequireCache, account: &mut OverlayAccount, db: &StateDb<'a>,
    ) -> bool {
        if let RequireCache::None = require {
            return true;
        }

        trace!("update_account_cache account={:?}", account);
        if account.is_cached() {
            return true;
        }

        let _hash = account.code_hash();
        match require {
            RequireCache::None => true,
            RequireCache::Code | RequireCache::CodeSize => {
                account.cache_code(db).is_some()
            }
        }
    }

    fn commit_metadata(&mut self) -> DbResult<()> {
        self.db.set_interest_rate(&self.interest_rate)?;
        self.db
            .set_accumulate_interest_rate(&self.accumulate_interest_rate)?;
        self.db.set_total_tokens(&self.total_tokens)?;
        self.db.set_total_bank_tokens(&self.total_bank_tokens)?;
        self.db
            .set_total_storage_tokens(&self.total_storage_tokens)?;
        Ok(())
    }

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
                for (_, value) in storage_key_value {
                    let storage_value =
                        rlp::decode::<StorageValue>(value.as_ref())?;
                    self.sub_storage_balance(
                        &storage_value.owner,
                        &U256::from(RENTAL_PRICE_PER_STORAGE_KEY),
                    )?;
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
        self.commit_metadata()?;

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
        self.commit_metadata()?;

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
        &mut self, address: &Address, code: Bytes,
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
        .init_code(code);
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
        self.ensure_cached(address, RequireCache::None, false, |acc| {
            acc.is_some()
        })
    }

    pub fn exists_and_not_null(&self, address: &Address) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::None, false, |acc| {
            acc.map_or(false, |acc| !acc.is_null())
        })
    }

    pub fn exists_and_has_code_or_nonce(
        &self, address: &Address,
    ) -> DbResult<bool> {
        self.ensure_cached(address, RequireCache::CodeSize, false, |acc| {
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
        // TODO: consider both balance and bank_balance
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
        self.ensure_cached(address, RequireCache::None, true, |acc| {
            acc.map_or(H256::zero(), |account| {
                account.storage_at(&self.db, key).unwrap_or(H256::zero())
            })
        })
    }

    /// TODO: Remove this function since it is not used outside.
    pub fn original_storage_at(
        &self, address: &Address, key: &H256,
    ) -> DbResult<H256> {
        self.ensure_cached(address, RequireCache::None, true, |acc| {
            acc.map_or(H256::zero(), |account| {
                account
                    .original_storage_at(&self.db, key)
                    .unwrap_or(H256::zero())
            })
        })
    }

    /// Get the value of storage at a specific checkpoint.
    /// TODO: Remove this function since it is not used outside.
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
                        } else if account.reset_storage {
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

        println!("kind={:?}", kind);

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

    fn ensure_cached<F, U>(
        &self, address: &Address, require: RequireCache, _check_null: bool,
        f: F,
    ) -> DbResult<U>
    where
        F: Fn(Option<&OverlayAccount>) -> U,
    {
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

        let mut maybe_acc = self.db.get_account(address)?.map(|acc| {
            OverlayAccount::new(address, acc, self.accumulate_interest_rate)
        });
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
                OverlayAccount::new(address, acc, self.accumulate_interest_rate)
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
        self.cache.borrow_mut().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        tests::new_state_manager_for_testing, StateIndex, StorageManager,
        StorageManagerTrait,
    };
    use cfx_types::{Address, BigEndianHash, U256};

    fn get_state(storage_manager: &StorageManager, epoch_id: EpochId) -> State {
        State::new(
            StateDb::new(
                storage_manager
                    .get_state_for_next_epoch(
                        StateIndex::new_for_test_only_delta_mpt(&epoch_id),
                    )
                    .unwrap()
                    .unwrap(),
            ),
            0.into(),
            VmFactory::default(),
        )
    }

    fn get_state_for_genesis_write(storage_manager: &StorageManager) -> State {
        State::new(
            StateDb::new(storage_manager.get_state_for_genesis_write()),
            0.into(),
            VmFactory::default(),
        )
    }

    #[test]
    fn checkpoint_basic() {
        let storage_manager = new_state_manager_for_testing();
        let mut state = get_state_for_genesis_write(&storage_manager);
        let address = Address::zero();
        state.checkpoint();
        state
            .add_balance(&address, &U256::from(69u64), CleanupMode::NoEmpty)
            .unwrap();
        assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
        state.discard_checkpoint();
        assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
        state.checkpoint();
        state
            .add_balance(&address, &U256::from(1u64), CleanupMode::NoEmpty)
            .unwrap();
        assert_eq!(state.balance(&address).unwrap(), U256::from(70u64));
        state.revert_to_checkpoint();
        assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
    }

    #[test]
    fn checkpoint_nested() {
        let storage_manager = new_state_manager_for_testing();
        let mut state = get_state_for_genesis_write(&storage_manager);
        let address = Address::zero();
        state.checkpoint();
        state.checkpoint();
        state
            .add_balance(&address, &U256::from(69u64), CleanupMode::NoEmpty)
            .unwrap();
        assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
        state.discard_checkpoint();
        assert_eq!(state.balance(&address).unwrap(), U256::from(69u64));
        state.revert_to_checkpoint();
        assert_eq!(state.balance(&address).unwrap(), U256::from(0));
    }

    #[test]
    fn checkpoint_revert_to_get_storage_at() {
        let storage_manager = new_state_manager_for_testing();
        let mut state = get_state_for_genesis_write(&storage_manager);
        let address = Address::zero();
        let key = BigEndianHash::from_uint(&U256::from(0));
        let c0 = state.checkpoint();
        let c1 = state.checkpoint();
        state
            .set_storage(
                &address,
                key,
                BigEndianHash::from_uint(&U256::from(1)),
                address,
            )
            .unwrap();

        assert_eq!(
            state.checkpoint_storage_at(c0, &address, &key).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &address, &key).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.storage_at(&address, &key).unwrap(),
            BigEndianHash::from_uint(&U256::from(1))
        );

        state.revert_to_checkpoint();
        assert_eq!(
            state.checkpoint_storage_at(c0, &address, &key).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.storage_at(&address, &key).unwrap(),
            BigEndianHash::from_uint(&U256::from(0))
        );
    }

    #[test]
    fn checkpoint_from_empty_get_storage_at() {
        let storage_manager = new_state_manager_for_testing();
        let mut state = get_state_for_genesis_write(&storage_manager);
        let a = Address::zero();
        let k = BigEndianHash::from_uint(&U256::from(0));
        let k2 = BigEndianHash::from_uint(&U256::from(1));

        assert_eq!(
            state.storage_at(&a, &k).unwrap(),
            BigEndianHash::from_uint(&U256::from(0))
        );
        state.clear();

        let c0 = state.checkpoint();
        state.new_contract(&a, U256::zero(), U256::zero()).unwrap();
        let c1 = state.checkpoint();
        state
            .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(1)), a)
            .unwrap();
        let c2 = state.checkpoint();
        let c3 = state.checkpoint();
        state
            .set_storage(&a, k2, BigEndianHash::from_uint(&U256::from(3)), a)
            .unwrap();
        state
            .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(3)), a)
            .unwrap();
        let c4 = state.checkpoint();
        state
            .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(4)), a)
            .unwrap();
        let c5 = state.checkpoint();

        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c2, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c3, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c4, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(3)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c5, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(4)))
        );

        state.check_storage_balance();
        state.discard_checkpoint(); // Commit/discard c5.
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c2, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c3, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c4, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(3)))
        );

        state.revert_to_checkpoint(); // Revert to c4.
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c2, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c3, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );

        state.check_storage_balance();
        state.discard_checkpoint(); // Commit/discard c3.
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c2, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );

        state.revert_to_checkpoint(); // Revert to c2.
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );

        state.check_storage_balance();
        state.discard_checkpoint(); // Commit/discard c1.
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
    }

    #[test]
    fn checkpoint_get_storage_at() {
        let storage_manager = new_state_manager_for_testing();
        let mut state = get_state_for_genesis_write(&storage_manager);
        let a = Address::zero();
        let k = BigEndianHash::from_uint(&U256::from(0));
        let k2 = BigEndianHash::from_uint(&U256::from(1));

        state.checkpoint();
        state
            .set_storage(
                &a,
                k,
                BigEndianHash::from_uint(&U256::from(0xffff)),
                a,
            )
            .unwrap();
        state.check_storage_balance();
        state.discard_checkpoint();
        state
            .commit(BigEndianHash::from_uint(&U256::from(1u64)))
            .unwrap();
        state.clear();

        state = get_state(
            &storage_manager,
            BigEndianHash::from_uint(&U256::from(1u64)),
        );
        assert_eq!(
            state.storage_at(&a, &k).unwrap(),
            BigEndianHash::from_uint(&U256::from(0xffff))
        );
        state.clear();

        let cm1 = state.checkpoint();
        let c0 = state.checkpoint();
        state.new_contract(&a, U256::zero(), U256::zero()).unwrap();
        let c1 = state.checkpoint();
        state
            .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(1)), a)
            .unwrap();
        let c2 = state.checkpoint();
        let c3 = state.checkpoint();
        state
            .set_storage(&a, k2, BigEndianHash::from_uint(&U256::from(3)), a)
            .unwrap();
        state
            .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(3)), a)
            .unwrap();
        let c4 = state.checkpoint();
        state
            .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(4)), a)
            .unwrap();
        let c5 = state.checkpoint();

        assert_eq!(
            state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c2, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c3, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c4, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(3)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c5, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(4)))
        );

        state.check_storage_balance();
        state.discard_checkpoint(); // Commit/discard c5.
        assert_eq!(
            state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c2, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c3, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c4, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(3)))
        );

        state.revert_to_checkpoint(); // Revert to c4.
        assert_eq!(
            state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c2, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c3, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );

        state.check_storage_balance();
        state.discard_checkpoint(); // Commit/discard c3.
        assert_eq!(
            state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c2, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(1)))
        );

        state.revert_to_checkpoint(); // Revert to c2.
        assert_eq!(
            state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0)))
        );

        state.check_storage_balance();
        state.discard_checkpoint(); // Commit/discard c1.
        assert_eq!(
            state.checkpoint_storage_at(cm1, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
        assert_eq!(
            state.checkpoint_storage_at(c0, &a, &k).unwrap(),
            Some(BigEndianHash::from_uint(&U256::from(0xffff)))
        );
    }

    #[test]
    fn kill_account_with_checkpoints() {
        let storage_manager = new_state_manager_for_testing();
        let mut state = get_state_for_genesis_write(&storage_manager);
        let a = Address::zero();
        let k = BigEndianHash::from_uint(&U256::from(0));
        state.checkpoint();
        state
            .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(1)), a)
            .unwrap();
        state.checkpoint();
        state.kill_account(&a);

        assert_eq!(
            state.storage_at(&a, &k).unwrap(),
            BigEndianHash::from_uint(&U256::from(0))
        );
        state.revert_to_checkpoint();
        assert_eq!(
            state.storage_at(&a, &k).unwrap(),
            BigEndianHash::from_uint(&U256::from(1))
        );
    }

    #[test]
    fn create_contract_fail() {
        let storage_manager = new_state_manager_for_testing();
        let mut state = get_state_for_genesis_write(&storage_manager);
        let a = Address::from_low_u64_be(1000);

        state.checkpoint(); // c1
        state.new_contract(&a, U256::zero(), U256::zero()).unwrap();
        state
            .add_balance(&a, &U256::from(1), CleanupMode::ForceCreate)
            .unwrap();
        state.checkpoint(); // c2
        state
            .add_balance(&a, &U256::from(1), CleanupMode::ForceCreate)
            .unwrap();
        state.check_storage_balance();
        state.discard_checkpoint(); // discard c2
        state.revert_to_checkpoint(); // revert to c1
        assert_eq!(state.exists(&a).unwrap(), false);

        state
            .commit(BigEndianHash::from_uint(&U256::from(1)))
            .unwrap();
    }

    #[test]
    fn create_contract_fail_previous_storage() {
        let storage_manager = new_state_manager_for_testing();
        let mut state = get_state_for_genesis_write(&storage_manager);
        let a = Address::from_low_u64_be(1000);
        let k = BigEndianHash::from_uint(&U256::from(0));

        state.checkpoint();
        state
            .set_storage(
                &a,
                k,
                BigEndianHash::from_uint(&U256::from(0xffff)),
                a,
            )
            .unwrap();
        state.check_storage_balance();
        state.discard_checkpoint();
        state
            .commit(BigEndianHash::from_uint(&U256::from(1)))
            .unwrap();
        state.clear();

        assert_eq!(
            state.storage_at(&a, &k).unwrap(),
            BigEndianHash::from_uint(&U256::from(0xffff))
        );
        state.clear();
        state = get_state(
            &storage_manager,
            BigEndianHash::from_uint(&U256::from(1)),
        );

        state.checkpoint(); // c1
        state.new_contract(&a, U256::zero(), U256::zero()).unwrap();
        state.checkpoint(); // c2
        state
            .set_storage(&a, k, BigEndianHash::from_uint(&U256::from(2)), a)
            .unwrap();
        state.revert_to_checkpoint(); // revert to c2
        assert_eq!(
            state.storage_at(&a, &k).unwrap(),
            BigEndianHash::from_uint(&U256::from(0))
        );
        state.revert_to_checkpoint(); // revert to c1
        assert_eq!(
            state.storage_at(&a, &k).unwrap(),
            BigEndianHash::from_uint(&U256::from(0xffff))
        );

        state
            .commit(BigEndianHash::from_uint(&U256::from(2)))
            .unwrap();
    }
}
