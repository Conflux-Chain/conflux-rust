use super::{
    AccountEntry, AccountEntryProtectedMethods, OverlayAccount, State,
};
use cfx_statedb::{
    ErrorKind as DbErrorKind, Result as DbResult, StateDb, StateDbExt,
};
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, U256};
use parking_lot::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLockReadGuard,
    RwLockWriteGuard,
};
use std::collections::hash_map::{
    Entry::{Occupied, Vacant},
    VacantEntry,
};

pub type AccountReadGuard<'a> = MappedRwLockReadGuard<'a, OverlayAccount>;
pub type AccountWriteGuard<'a> = MappedRwLockWriteGuard<'a, OverlayAccount>;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum RequireCache {
    None,
    Code,
    DepositList,
    VoteStakeList,
}

impl State {
    pub(super) fn read_account_lock(
        &self, address: &AddressWithSpace,
    ) -> DbResult<Option<AccountReadGuard>> {
        self.read_account_ext_lock(address, RequireCache::None)
    }

    pub(super) fn read_native_account_lock(
        &self, address: &Address,
    ) -> DbResult<Option<AccountReadGuard>> {
        self.read_account_lock(&address.with_native_space())
    }

    pub(super) fn read_account_ext_lock(
        &self, address: &AddressWithSpace, require: RequireCache,
    ) -> DbResult<Option<AccountReadGuard>> {
        let mut cache = self.cache.write();
        let account_entry = match cache.entry(*address) {
            Occupied(e) => e.into_mut(),
            Vacant(e) => self.load_to_cache(e)?,
        };

        Self::load_account_ext_fields(require, account_entry, &self.db)?;

        Ok(if !account_entry.is_db_absent() {
            Some(RwLockReadGuard::map(
                RwLockWriteGuard::downgrade(cache),
                |cache| cache.get(address).unwrap().account().unwrap(),
            ))
        } else {
            None
        })
    }

    fn should_load_ext_fields(
        require: RequireCache, account: &OverlayAccount,
    ) -> bool {
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
    pub fn write_account_lock(
        &self, address: &AddressWithSpace,
    ) -> DbResult<AccountWriteGuard> {
        self.require_exists(address, false)
    }

    pub(super) fn write_native_account_lock(
        &self, address: &Address,
    ) -> DbResult<AccountWriteGuard> {
        self.write_account_lock(&address.with_native_space())
    }

    pub(super) fn write_account_ext_lock(
        &self, address: &AddressWithSpace, require: RequireCache,
    ) -> DbResult<AccountWriteGuard> {
        Ok(match require {
            RequireCache::None => self.require_exists(address, false)?,
            RequireCache::Code => self.require_exists(address, true)?,
            RequireCache::DepositList => {
                let mut acc = self.require_exists(address, false)?;
                acc.cache_ext_fields(true, false, &self.db)?;
                acc
            }
            RequireCache::VoteStakeList => {
                let mut acc = self.require_exists(address, false)?;
                acc.cache_ext_fields(false, true, &self.db)?;
                acc
            }
        })
    }

    pub(super) fn write_account_or_new_lock(
        &self, address: &AddressWithSpace,
    ) -> DbResult<AccountWriteGuard> {
        self.require_or_new_basic_account(address)
    }

    fn require_exists(
        &self, address: &AddressWithSpace, require_code: bool,
    ) -> DbResult<AccountWriteGuard> {
        fn no_account_is_an_error(
            address: &AddressWithSpace,
        ) -> DbResult<OverlayAccount> {
            bail!(DbErrorKind::IncompleteDatabase(address.address));
        }
        self.require_or_set(address, require_code, no_account_is_an_error)
    }

    fn require_or_new_basic_account(
        &self, address: &AddressWithSpace,
    ) -> DbResult<AccountWriteGuard> {
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
    ) -> DbResult<AccountWriteGuard>
    where F: FnOnce(&AddressWithSpace) -> DbResult<OverlayAccount> {
        let mut cache = self.cache.write();
        let account_entry = match cache.entry(*address) {
            Occupied(e) => e.into_mut(),
            Vacant(e) => self.load_to_cache(e)?,
        };

        // Save the value before modification into the checkpoint.
        self.clone_to_checkpoint(*address, account_entry);

        // Set the dirty flag.
        if let AccountEntry::Cached(_, dirty_bit) = account_entry {
            *dirty_bit = true;
        } else {
            *account_entry = AccountEntry::new_dirty(default(address)?);
        }

        if require_code {
            Self::load_account_ext_fields(
                RequireCache::Code,
                account_entry,
                &self.db,
            )?;
        }

        Ok(RwLockWriteGuard::map(cache, |c| {
            c.get_mut(address)
                .expect("Entry known to exist in the cache.")
                .account_mut()
                .expect("Required account must exist.")
        }))
    }
}

impl State {
    /// Load required account data from the databases. Returns whether the
    /// cache succeeds.
    fn load_account_ext_fields(
        require: RequireCache, account_entry: &mut AccountEntry, db: &StateDb,
    ) -> DbResult<()> {
        let account = unwrap_or_return!(account_entry.account_mut(), Ok(()));

        if !Self::should_load_ext_fields(require, account) {
            return Ok(());
        }

        match require {
            RequireCache::None => Ok(()),
            RequireCache::Code => account.cache_code(db),
            RequireCache::DepositList => account.cache_ext_fields(
                true,  /* cache_deposit_list */
                false, /* cache_vote_list */
                db,
            ),
            RequireCache::VoteStakeList => account.cache_ext_fields(
                false, /* cache_deposit_list */
                true,  /* cache_vote_list */
                db,
            ),
        }
    }

    fn load_to_cache<'a>(
        &self, e: VacantEntry<'a, AddressWithSpace, AccountEntry>,
    ) -> DbResult<&'a mut AccountEntry> {
        // load operation does not involve the checkpoint
        let address = e.key();
        let account = self
            .db
            .get_account(address)?
            .map(|acc| OverlayAccount::from_loaded(address, acc));
        Ok(e.insert(AccountEntry::new_loaded(account)))
    }
}
