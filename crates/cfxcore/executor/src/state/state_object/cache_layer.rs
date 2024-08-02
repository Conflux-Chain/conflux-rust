//! Cache Layer in State: Implements a read-through write-back cache logic and
//! provides interfaces for reading and writing account data. It also handles
//! the logic for loading extension fields of an account.

use super::{AccountEntry, OverlayAccount, RequireFields, State};
use crate::unwrap_or_return;
use cfx_statedb::{
    ErrorKind as DbErrorKind, Result as DbResult, StateDb, StateDbExt,
};
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, U256};
use parking_lot::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLockReadGuard,
    RwLockWriteGuard,
};
use std::collections::{
    hash_map::Entry::{Occupied, Vacant},
    HashMap,
};

pub type AccountReadGuard<'a> = MappedRwLockReadGuard<'a, OverlayAccount>;
pub type AccountWriteGuard<'a> = MappedRwLockWriteGuard<'a, OverlayAccount>;

impl State {
    /// A convenience function of `read_account_ext_lock`
    pub(super) fn read_account_lock(
        &self, address: &AddressWithSpace,
    ) -> DbResult<Option<AccountReadGuard>> {
        self.read_account_ext_lock(address, RequireFields::None)
    }

    /// A convenience function of `read_account_ext_lock`
    pub(super) fn read_native_account_lock(
        &self, address: &Address,
    ) -> DbResult<Option<AccountReadGuard>> {
        self.read_account_lock(&address.with_native_space())
    }

    /// Requests an immutable reference of an account through the cache by the
    /// address and required, returning a reference with a read lock guard.
    /// It returns `None` if the account doesn't exist.
    // FIXME: the current implementation may affect prefetch performance.
    pub(super) fn read_account_ext_lock(
        &self, address: &AddressWithSpace, require: RequireFields,
    ) -> DbResult<Option<AccountReadGuard>> {
        let mut cache = self.cache.write();
        let account_entry =
            Self::fetch_account_mut(&mut cache, &self.db, address, require)?;

        Ok(if !account_entry.is_db_absent() {
            Some(RwLockReadGuard::map(
                RwLockWriteGuard::downgrade(cache),
                |cache| cache.get(address).unwrap().account().unwrap(),
            ))
        } else {
            None
        })
    }

    /// Prefetch an account with required extension fields. This function does
    /// not hold a write lock during loading db, enabling parallel prefetch.
    pub(super) fn prefetch(
        &self, address: &AddressWithSpace, require: RequireFields,
    ) -> DbResult<()> {
        if let Some(account_entry) = self.cache.read().get(address) {
            if let Some(account) = account_entry.account() {
                if !account.should_load_ext_fields(require) {
                    // Return if the account has been loaded and no more field
                    // needs to be loaded
                    return Ok(());
                }
            } else {
                // Return if the account is known be absent in db.
                return Ok(());
            }
        }

        // Performance Consideration: If an account already exists but
        // additional fields are requested, this implementation reloads
        // the account, which may result in some performance loss.
        // However, to ensure code clarity and maintainability, and to safeguard
        // checkpoint logic integrity, we choose not to optimize this
        // behavior. Currently, this case does not occur in the existing
        // codebase.

        // Load the account and insert to cache
        let mut account_entry =
            AccountEntry::new_loaded(self.db.get_account(address)?);
        Self::load_account_ext_fields(require, &mut account_entry, &self.db)?;

        self.cache.write().insert(*address, account_entry);
        Ok(())
    }
}

impl State {
    /// A convenience function of `write_account_ext_lock`
    pub fn write_account_lock(
        &self, address: &AddressWithSpace,
    ) -> DbResult<AccountWriteGuard> {
        self.write_account_ext_lock(address, RequireFields::None)
    }

    /// A convenience function of `write_account_ext_lock`
    pub(super) fn write_native_account_lock(
        &self, address: &Address,
    ) -> DbResult<AccountWriteGuard> {
        self.write_account_lock(&address.with_native_space())
    }

    /// Requests a mutable reference of an account through the cache by the
    /// address and required, returning a reference with a write lock guard.
    /// It asserts a fail if the account doesn't exist.
    pub(super) fn write_account_ext_lock(
        &self, address: &AddressWithSpace, require: RequireFields,
    ) -> DbResult<AccountWriteGuard> {
        fn no_account_is_an_error(
            address: &AddressWithSpace,
        ) -> DbResult<OverlayAccount> {
            bail!(DbErrorKind::IncompleteDatabase(address.address));
        }
        self.write_account_inner(address, require, no_account_is_an_error)
    }

    /// Requests a mutable reference of an account through the cache by the
    /// address, returning a reference with a write lock guard. It initiates a
    /// new account if the account doesn't exist.
    pub(super) fn write_account_or_new_lock(
        &self, address: &AddressWithSpace,
    ) -> DbResult<AccountWriteGuard> {
        fn init_if_no_account(
            address: &AddressWithSpace,
        ) -> DbResult<OverlayAccount> {
            // It is guaranteed that the address is valid.

            // Note that it is possible to first send money to a pre-calculated
            // contract address and then deploy contracts. So we are
            // going to *allow* sending to a contract address and
            // use new_basic() to create a *stub* there. Because the contract
            // serialization is a super-set of the normal address
            // serialization, this should just work.
            Ok(OverlayAccount::new_basic(address, U256::zero()))
        }
        self.write_account_inner(
            address,
            RequireFields::None,
            init_if_no_account,
        )
    }

    /// Requests an account via a read-through cache, makes a checkpoint in
    /// needed, handles "the account doesn't exist" by the passed in function,
    /// and sets the dirty bit.
    fn write_account_inner<F>(
        &self, address: &AddressWithSpace, require: RequireFields, default: F,
    ) -> DbResult<AccountWriteGuard>
    where F: Fn(&AddressWithSpace) -> DbResult<OverlayAccount> {
        let mut cache = self.cache.write();
        let account_entry =
            Self::fetch_account_mut(&mut cache, &self.db, address, require)?;

        // Save the value before modification into the checkpoint.
        self.copy_cache_entry_to_checkpoint(*address, account_entry);

        // Set the dirty flag in cache.
        if let AccountEntry::Cached(_, dirty_bit) = account_entry {
            *dirty_bit = true;
        } else {
            *account_entry = AccountEntry::new_dirty(default(address)?);
        }

        Ok(RwLockWriteGuard::map(cache, |c| {
            c.get_mut(address)
                .expect("Entry known to exist in the cache.")
                .dirty_account_mut()
                .expect("Required account must exist.")
        }))
    }
}

impl State {
    /// Retrieves data using a read-through caching strategy and automatically
    /// loads extension fields as required.
    fn fetch_account_mut<'a>(
        cache: &'a mut HashMap<AddressWithSpace, AccountEntry>, db: &StateDb,
        address: &AddressWithSpace, require: RequireFields,
    ) -> DbResult<&'a mut AccountEntry> {
        let account_entry = match cache.entry(*address) {
            Occupied(e) => e.into_mut(),
            Vacant(e) => {
                let address = *e.key();
                e.insert(AccountEntry::new_loaded(db.get_account(&address)?))
            }
        };
        Self::load_account_ext_fields(require, account_entry, db)?;
        Ok(account_entry)
    }

    /// Load required extension fields of an account as required.
    fn load_account_ext_fields(
        require: RequireFields, account_entry: &mut AccountEntry, db: &StateDb,
    ) -> DbResult<()> {
        let account = unwrap_or_return!(account_entry.account_mut(), Ok(()));

        if !account.should_load_ext_fields(require) {
            return Ok(());
        }

        match require {
            RequireFields::None => Ok(()),
            RequireFields::Code => account.cache_code(db),
            RequireFields::DepositList => account.cache_ext_fields(
                true,  /* cache_deposit_list */
                false, /* cache_vote_list */
                db,
            ),
            RequireFields::VoteStakeList => account.cache_ext_fields(
                false, /* cache_deposit_list */
                true,  /* cache_vote_list */
                db,
            ),
        }
    }
}
