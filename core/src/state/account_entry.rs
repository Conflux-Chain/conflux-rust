// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::{Bytes, ToPretty},
    hash::{keccak, KECCAK_EMPTY},
    statedb::{Result as DbResult, StateDb},
};
use cfx_types::{Address, H256, U256};
use primitives::Account;
use std::{cell::RefCell, collections::HashMap, sync::Arc};

#[derive(Debug)]
/// Single account in the system.
/// Keeps track of changes to the code and storage.
/// The changes are applied in `commit_storage` and `commit_code`
pub struct OverlayAccount {
    address: Address,

    // Balance of the account.
    balance: U256,
    // Nonce of the account,
    nonce: U256,

    storage_cache: RefCell<HashMap<H256, H256>>,
    storage_changes: HashMap<H256, H256>,

    // Code hash of the account.
    code_hash: H256,
    // Size of the acccount code.
    code_size: Option<usize>,
    // Code cache of the account.
    code_cache: Arc<Bytes>,

    pub reset_storage: bool,
}

impl OverlayAccount {
    pub fn new(address: &Address, account: Account) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance: account.balance,
            nonce: account.nonce,
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            code_hash: account.code_hash,
            code_size: None,
            code_cache: Arc::new(vec![]),
            reset_storage: false,
        }
    }

    pub fn new_basic(address: &Address, balance: U256, nonce: U256) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce,
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            code_hash: KECCAK_EMPTY,
            code_size: None,
            code_cache: Arc::new(vec![]),
            reset_storage: false,
        }
    }

    pub fn new_contract(
        address: &Address, balance: U256, nonce: U256, reset_storage: bool,
    ) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce,
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            code_hash: KECCAK_EMPTY,
            code_size: None,
            code_cache: Arc::new(vec![]),
            reset_storage,
        }
    }

    pub fn as_account(&self) -> Account {
        Account {
            address: self.address.clone(),
            balance: self.balance.clone(),
            nonce: self.nonce.clone(),
            code_hash: self.code_hash.clone(),
        }
    }

    pub fn address(&self) -> &Address { &self.address }

    pub fn balance(&self) -> &U256 { &self.balance }

    pub fn nonce(&self) -> &U256 { &self.nonce }

    pub fn code_hash(&self) -> H256 { self.code_hash.clone() }

    pub fn code_size(&self) -> Option<usize> { self.code_size.clone() }

    pub fn code(&self) -> Option<Arc<Bytes>> {
        if self.code_hash != KECCAK_EMPTY && self.code_cache.is_empty() {
            None
        } else {
            Some(self.code_cache.clone())
        }
    }

    #[allow(dead_code)]
    pub fn reset_storage(&mut self) { self.reset_storage = true; }

    pub fn is_cached(&self) -> bool {
        !self.code_cache.is_empty()
            || (self.code_cache.is_empty() && self.code_hash == KECCAK_EMPTY)
    }

    pub fn is_null(&self) -> bool {
        self.balance.is_zero()
            && self.nonce.is_zero()
            && self.code_hash == KECCAK_EMPTY
    }

    pub fn is_basic(&self) -> bool { self.code_hash == KECCAK_EMPTY }

    pub fn inc_nonce(&mut self) { self.nonce = self.nonce + U256::from(1u8); }

    pub fn add_balance(&mut self, by: &U256) {
        self.balance = self.balance + *by;
    }

    pub fn sub_balance(&mut self, by: &U256) {
        assert!(self.balance >= *by);
        self.balance = self.balance - *by;
    }

    pub fn cache_code<'a>(&mut self, db: &StateDb<'a>) -> Option<Arc<Bytes>> {
        trace!("OverlayAccount::cache_code: ic={}; self.code_hash={:?}, self.code_cache={}", self.is_cached(), self.code_hash, self.code_cache.pretty());

        if self.is_cached() {
            return Some(self.code_cache.clone());
        }

        match db.get_raw(&db.code_key(&self.address, &self.code_hash)) {
            Ok(Some(code)) => {
                self.code_size = Some(code.len());
                self.code_cache = Arc::new(code.to_vec());
                Some(self.code_cache.clone())
            }
            _ => {
                warn!("Failed reverse get of {}", self.code_hash);
                None
            }
        }
    }

    pub fn clone_basic(&self) -> Self {
        OverlayAccount {
            address: self.address.clone(),
            balance: self.balance.clone(),
            nonce: self.nonce.clone(),
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            code_hash: self.code_hash.clone(),
            code_size: self.code_size.clone(),
            code_cache: self.code_cache.clone(),
            reset_storage: self.reset_storage,
        }
    }

    pub fn clone_dirty(&self) -> Self {
        let mut account = self.clone_basic();
        account.storage_changes = self.storage_changes.clone();
        account.reset_storage = self.reset_storage;
        account
    }

    pub fn set_storage(&mut self, key: H256, value: H256) {
        self.storage_changes.insert(key, value);
    }

    pub fn cached_storage_at(&self, key: &H256) -> Option<H256> {
        if let Some(value) = self.storage_changes.get(key) {
            return Some(value.clone());
        }
        if let Some(value) = self.storage_cache.borrow().get(key) {
            return Some(value.clone());
        }
        None
    }

    pub fn storage_at<'a>(
        &self, db: &StateDb<'a>, key: &H256,
    ) -> DbResult<H256> {
        if let Some(value) = self.cached_storage_at(key) {
            return Ok(value);
        }
        if self.reset_storage {
            Ok(H256::zero())
        } else {
            Self::get_and_cache_storage(
                &mut self.storage_cache.borrow_mut(),
                db,
                &self.address,
                key,
            )
        }
    }

    pub fn original_storage_at<'a>(
        &self, db: &StateDb<'a>, key: &H256,
    ) -> DbResult<H256> {
        if let Some(value) = self.storage_cache.borrow().get(key) {
            return Ok(value.clone());
        }
        Self::get_and_cache_storage(
            &mut self.storage_cache.borrow_mut(),
            db,
            &self.address,
            key,
        )
    }

    fn get_and_cache_storage<'a>(
        storage_cache: &mut HashMap<H256, H256>, db: &StateDb<'a>,
        address: &Address, key: &H256,
    ) -> DbResult<H256>
    {
        let value = db
            .get::<H256>(&db.storage_key(address, key.as_ref()))
            .expect("get_and_cache_storage failed")
            .unwrap_or_else(|| H256::zero());
        storage_cache.insert(key.clone(), value.clone());

        Ok(value)
    }

    pub fn init_code(&mut self, code: Bytes) {
        self.code_hash = keccak(&code);
        self.code_cache = Arc::new(code);
        self.code_size = Some(self.code_cache.len());
    }

    pub fn overwrite_with(&mut self, other: OverlayAccount) {
        self.balance = other.balance;
        self.nonce = other.nonce;
        self.code_hash = other.code_hash;
        self.code_cache = other.code_cache;
        self.code_size = other.code_size;
        self.storage_cache = other.storage_cache;
        self.storage_changes = other.storage_changes;
        self.reset_storage = other.reset_storage;
    }

    pub fn commit<'a>(&mut self, db: &mut StateDb<'a>) -> DbResult<()> {
        if self.reset_storage {
            db.delete_all(&db.storage_root_key(&self.address))?;
            db.delete_all(&db.code_root_key(&self.address))?;
        }

        for (k, v) in self.storage_changes.drain() {
            let address_key = db.storage_key(&self.address, k.as_ref());

            match v.is_zero() {
                true => db.delete(&address_key)?,
                false => {
                    db.set::<H256>(&address_key, &H256::from(U256::from(v)))?
                }
            }
            self.storage_cache.borrow_mut().insert(k, v);
        }
        match self.code() {
            None => {}
            Some(code) => {
                if !code.is_empty() {
                    db.set_raw(
                        &db.code_key(&self.address, &self.code_hash),
                        code.as_ref().clone().into_boxed_slice(),
                    )?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
/// Account modification state. Used to check if the account was
/// Modified in between commits and overall.
#[allow(dead_code)]
pub enum AccountState {
    /// Account was loaded from disk and never modified in this state object.
    CleanFresh,
    /// Account was loaded from the global cache and never modified.
    CleanCached,
    /// Account has been modified and is not committed to the trie yet.
    /// This is set if any of the account data is changed, including
    /// storage and code.
    Dirty,
    /// Account was modified and committed to the trie.
    Committed,
}

#[derive(Debug)]
/// In-memory copy of the account data. Holds the optional account
/// and the modification status.
/// Account entry can contain existing (`Some`) or non-existing
/// account (`None`)
pub struct AccountEntry {
    /// Account proxy. `None` if account known to be non-existant.
    pub account: Option<OverlayAccount>,
    /// Unmodified account balance.
    pub old_balance: Option<U256>,
    /// Entry state.
    pub state: AccountState,
}

impl AccountEntry {
    pub fn is_dirty(&self) -> bool { self.state == AccountState::Dirty }

    pub fn overwrite_with(&mut self, other: AccountEntry) {
        self.state = other.state;
        match other.account {
            Some(acc) => {
                if let Some(ref mut ours) = self.account {
                    ours.overwrite_with(acc);
                } else {
                    self.account = Some(acc);
                }
            }
            None => self.account = None,
        }
    }

    /// Clone dirty data into new `AccountEntry`. This includes
    /// basic account data and modified storage keys.
    /// Returns None if clean.
    #[allow(dead_code)]
    pub fn clone_if_dirty(&self) -> Option<AccountEntry> {
        match self.is_dirty() {
            true => Some(self.clone_dirty()),
            false => None,
        }
    }

    /// Clone dirty data into new `AccountEntry`. This includes
    /// basic account data and modified storage keys.
    pub fn clone_dirty(&self) -> AccountEntry {
        AccountEntry {
            old_balance: self.old_balance,
            account: self.account.as_ref().map(OverlayAccount::clone_dirty),
            state: self.state,
        }
    }

    pub fn new_dirty(account: Option<OverlayAccount>) -> AccountEntry {
        AccountEntry {
            old_balance: account.as_ref().map(|acc| acc.balance().clone()),
            account,
            state: AccountState::Dirty,
        }
    }

    pub fn new_clean(account: Option<OverlayAccount>) -> AccountEntry {
        AccountEntry {
            old_balance: account.as_ref().map(|acc| acc.balance().clone()),
            account,
            state: AccountState::CleanFresh,
        }
    }

    pub fn exists_and_is_null(&self) -> bool {
        self.account.as_ref().map_or(false, |acc| acc.is_null())
    }
}
