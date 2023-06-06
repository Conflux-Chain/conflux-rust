use super::State;

use parking_lot::{
    lock_api::{MappedRwLockReadGuard, RwLockReadGuard},
    MappedRwLockWriteGuard, RawRwLock, RwLockUpgradableReadGuard,
    RwLockWriteGuard,
};

use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, U256};

use cfx_statedb::{ErrorKind as DbErrorKind, Result as DbResult, StateDbExt};

use super::{
    account_entry::{AccountEntry, AccountState},
    AccountEntryProtectedMethods, RequireCache,
};
pub use super::{
    account_entry::{OverlayAccount, COMMISSION_PRIVILEGE_SPECIAL_KEY},
    substate::{cleanup_mode, CallStackInfo, Substate},
};

pub type AccountReadGuard<'a> =
    MappedRwLockReadGuard<'a, RawRwLock, OverlayAccount>;

impl State {
    pub(super) fn read_native_account<'a>(
        &'a self, address: &Address,
    ) -> DbResult<Option<AccountReadGuard<'a>>> {
        self.read_account(&address.with_native_space())
    }

    pub(super) fn read_account<'a>(
        &'a self, address: &AddressWithSpace,
    ) -> DbResult<Option<AccountReadGuard<'a>>> {
        self.read_account_ext(address, RequireCache::None)
    }

    pub(super) fn read_account_ext<'a>(
        &'a self, address: &AddressWithSpace, require: RequireCache,
    ) -> DbResult<Option<AccountReadGuard<'a>>> {
        let as_account_guard = |guard| {
            MappedRwLockReadGuard::map(guard, |entry: &AccountEntry| {
                entry.account.as_ref().unwrap()
            })
        };

        // Return immediately when there is no need to have db operation.
        if let Ok(guard) =
            RwLockReadGuard::try_map(self.cache.read(), |cache| {
                cache.get(address)
            })
        {
            if let Some(account) = &guard.account {
                let needs_update = Self::needs_update(require, account);
                if !needs_update {
                    return Ok(Some(as_account_guard(guard)));
                }
            } else {
                return Ok(None);
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
                    maybe_acc.address().address.clone(),
                )
                .into());
            }
        }

        let entry_guard = RwLockReadGuard::map(
            RwLockWriteGuard::downgrade(cache_write_lock),
            |cache| cache.get(address).unwrap(),
        );

        Ok(if entry_guard.account.is_some() {
            Some(as_account_guard(entry_guard))
        } else {
            None
        })
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
}

impl State {
    pub(super) fn write_account_ext(
        &self, address: &AddressWithSpace, require: RequireCache,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        Ok(match require {
            RequireCache::None => self.require_exists(address, false)?,
            RequireCache::Code => self.require_exists(address, true)?,
            RequireCache::DepositList => {
                let mut acc = self.require_exists(address, false)?;
                acc.cache_staking_info(true, false, &self.db)?;
                acc
            }
            RequireCache::VoteStakeList => {
                let mut acc = self.require_exists(address, false)?;
                acc.cache_staking_info(false, true, &self.db)?;
                acc
            }
        })
    }

    pub(super) fn write_account(
        &self, address: &AddressWithSpace,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        self.require_exists(address, false)
    }

    pub(super) fn write_native_account(
        &self, address: &Address,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        self.write_account(&address.with_native_space())
    }

    pub(super) fn require_exists(
        &self, address: &AddressWithSpace, require_code: bool,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        fn no_account_is_an_error(
            address: &AddressWithSpace,
        ) -> DbResult<OverlayAccount> {
            bail!(DbErrorKind::IncompleteDatabase(address.address));
        }
        self.require_or_set(address, require_code, no_account_is_an_error)
    }

    pub(super) fn require_or_new_basic_account(
        &self, address: &AddressWithSpace,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>> {
        self.require_or_set(address, false, |address| {
            // It is guaranteed that the address is valid.

            // Note that it is possible to first send money to a pre-calculated
            // contract address and then deploy contracts. So we are
            // going to *allow* sending to a contract address and
            // use new_basic() to create a *stub* there. Because the contract
            // serialization is a super-set of the normal address
            // serialization, this should just work.
            Ok(OverlayAccount::new_basic(address, U256::zero()))
        })
    }

    fn require_or_set<F>(
        &self, address: &AddressWithSpace, require_code: bool, default: F,
    ) -> DbResult<MappedRwLockWriteGuard<OverlayAccount>>
    where F: FnOnce(&AddressWithSpace) -> DbResult<OverlayAccount> {
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
                bail!(DbErrorKind::IncompleteDatabase(address.address));
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
}
