// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::{Bytes, ToPretty},
    hash::{keccak, KECCAK_EMPTY},
    parameters::consensus_internal::INTEREST_RATE_SCALE,
    statedb::{Result as DbResult, StateDb},
};
use cfx_types::{Address, BigEndianHash, H256, U256};
use primitives::{Account, DepositInfo, StorageKey};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{cell::RefCell, collections::HashMap, sync::Arc};

#[derive(Default, Clone, Debug, RlpDecodable, RlpEncodable)]
pub struct StorageValue {
    pub value: H256,
    pub owner: Address,
}

#[derive(Debug)]
/// Single account in the system.
/// Keeps track of changes to the code and storage.
/// The changes are applied in `commit_storage` and `commit_code`
pub struct OverlayAccount {
    address: Address,

    /// Balance of the account.
    balance: U256,
    /// Nonce of the account,
    nonce: U256,

    /// This is a cache for storage change.
    storage_cache: RefCell<HashMap<H256, H256>>,
    storage_changes: HashMap<H256, H256>,
    /// This is a cache for storage ownership change.
    ownership_cache: RefCell<HashMap<H256, Option<Address>>>,
    ownership_changes: HashMap<H256, Address>,

    /// This is the number of tokens in bank and part of this will be used for
    /// storage.
    bank_balance: U256,
    /// This is the number of tokens in bank used for storage.
    storage_balance: U256,
    /// This is the accumulated interest rate at latest deposit.
    bank_ar: U256,
    /// This is a list of deposit history (`amount`, `deposit_time`), in sorted
    /// order of `deposit_time`.
    deposit_list: Vec<DepositInfo>,

    // Code hash of the account.
    code_hash: H256,
    // Size of the acccount code.
    code_size: Option<usize>,
    // Code cache of the account.
    code_cache: Arc<Bytes>,

    pub reset_storage: bool,
}

impl OverlayAccount {
    pub fn new(address: &Address, account: Account, ar: U256) -> Self {
        let mut overlay_account = OverlayAccount {
            address: address.clone(),
            balance: account.balance,
            nonce: account.nonce,
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            bank_balance: account.bank_balance,
            storage_balance: account.storage_balance,
            bank_ar: account.bank_ar,
            deposit_list: account.deposit_list.clone(),
            code_hash: account.code_hash,
            code_size: None,
            code_cache: Arc::new(vec![]),
            reset_storage: false,
        };
        overlay_account.bank_balance_settlement(ar);
        overlay_account
    }

    pub fn new_basic(address: &Address, balance: U256, nonce: U256) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce,
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            bank_balance: 0.into(),
            storage_balance: 0.into(),
            bank_ar: 0.into(),
            deposit_list: Vec::new(),
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
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            bank_balance: 0.into(),
            storage_balance: 0.into(),
            bank_ar: 0.into(),
            deposit_list: Vec::new(),
            code_hash: KECCAK_EMPTY,
            code_size: None,
            code_cache: Arc::new(vec![]),
            reset_storage,
        }
    }

    pub fn as_account(&self) -> Account {
        Account {
            address: self.address,
            balance: self.balance,
            nonce: self.nonce,
            code_hash: self.code_hash,
            bank_balance: self.bank_balance,
            storage_balance: self.storage_balance,
            bank_ar: self.bank_ar,
            deposit_list: self.deposit_list.clone(),
        }
    }

    fn bank_balance_settlement(&mut self, ar: U256) {
        if self.bank_ar == ar {
            return;
        }
        let capital = self.bank_balance - self.storage_balance;
        self.balance +=
            capital * (ar - self.bank_ar) / U256::from(INTEREST_RATE_SCALE);
        self.bank_ar = ar;
    }

    pub fn address(&self) -> &Address { &self.address }

    pub fn balance(&self) -> &U256 { &self.balance }

    pub fn bank_balance(&self) -> &U256 { &self.bank_balance }

    pub fn storage_balance(&self) -> &U256 { &self.storage_balance }

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

    pub fn deposit(&mut self, by: &U256, deposit_time: u64) {
        self.sub_balance(by);
        self.bank_balance += *by;
        // The `deposit_time` is naturally in sorted order.
        self.deposit_list.push(DepositInfo {
            amount: *by,
            deposit_time,
        })
    }

    pub fn withdraw(&mut self, by: &U256) {
        assert!(self.bank_balance - self.storage_balance >= *by);
        self.bank_balance -= *by;
        self.add_balance(by);
        let mut rest = *by;
        // We prefer to consume latest deposit, since it will maximize the
        // voting rights.
        while !rest.is_zero() {
            assert!(!self.deposit_list.is_empty());
            if rest >= self.deposit_list.last().unwrap().amount {
                rest -= self.deposit_list.last().unwrap().amount;
                self.deposit_list.pop();
            } else {
                self.deposit_list.last_mut().unwrap().amount -= rest;
                rest = 0.into();
            }
        }
    }

    pub fn add_storage_balance(&mut self, by: &U256) {
        self.storage_balance += *by;
        assert!(self.storage_balance <= self.bank_balance);
    }

    pub fn sub_storage_balance(&mut self, by: &U256) {
        assert!(self.storage_balance >= *by);
        self.storage_balance -= *by;
    }

    pub fn cache_code<'a>(&mut self, db: &StateDb<'a>) -> Option<Arc<Bytes>> {
        trace!("OverlayAccount::cache_code: ic={}; self.code_hash={:?}, self.code_cache={}", self.is_cached(), self.code_hash, self.code_cache.pretty());

        if self.is_cached() {
            return Some(self.code_cache.clone());
        }

        match db
            .get_raw(StorageKey::new_code_key(&self.address, &self.code_hash))
        {
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
            address: self.address,
            balance: self.balance,
            nonce: self.nonce,
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            bank_balance: self.bank_balance,
            storage_balance: self.storage_balance,
            bank_ar: self.bank_ar,
            deposit_list: self.deposit_list.clone(),
            code_hash: self.code_hash,
            code_size: self.code_size,
            code_cache: self.code_cache.clone(),
            reset_storage: self.reset_storage,
        }
    }

    pub fn clone_dirty(&self) -> Self {
        let mut account = self.clone_basic();
        account.storage_changes = self.storage_changes.clone();
        account.ownership_cache = self.ownership_cache.clone();
        account.ownership_changes = self.ownership_changes.clone();
        account
    }

    pub fn set_storage(&mut self, key: H256, value: H256, owner: Address) {
        self.storage_changes.insert(key, value);
        self.ownership_changes.insert(key, owner);
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
                &mut self.ownership_cache.borrow_mut(),
                db,
                &self.address,
                key,
            )
        }
    }

    /// TODO: Remove this function since it is not used outside.
    pub fn original_storage_at<'a>(
        &self, db: &StateDb<'a>, key: &H256,
    ) -> DbResult<H256> {
        if let Some(value) = self.storage_cache.borrow().get(key) {
            return Ok(value.clone());
        }
        Self::get_and_cache_storage(
            &mut self.storage_cache.borrow_mut(),
            &mut self.ownership_cache.borrow_mut(),
            db,
            &self.address,
            key,
        )
    }

    fn get_and_cache_storage<'a>(
        storage_cache: &mut HashMap<H256, H256>,
        ownership_cache: &mut HashMap<H256, Option<Address>>, db: &StateDb<'a>,
        address: &Address, key: &H256,
    ) -> DbResult<H256>
    {
        assert!(!ownership_cache.contains_key(key));
        if let Some(value) = db
            .get::<StorageValue>(StorageKey::new_storage_key(
                address,
                key.as_ref(),
            ))
            .expect("get_and_cache_storage failed")
        {
            storage_cache.insert(*key, value.value);
            ownership_cache.insert(*key, Some(value.owner));
            Ok(value.value)
        } else {
            storage_cache.insert(key.clone(), H256::zero());
            ownership_cache.insert(*key, None);
            Ok(H256::zero())
        }
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
        self.ownership_cache = other.ownership_cache;
        self.ownership_changes = other.ownership_changes;
        self.bank_balance = other.bank_balance;
        self.storage_balance = other.storage_balance;
        self.bank_ar = other.bank_ar;
        self.reset_storage = other.reset_storage;
    }

    /// Return the owner of `key` before this execution. If it is `None`, it
    /// means the value of the key is zero before this execution. Otherwise, the
    /// value of the key is nonzero.
    fn original_ownership_at<'a>(
        &self, db: &StateDb<'a>, key: &H256,
    ) -> Option<Address> {
        if let Some(value) = self.ownership_cache.borrow().get(key) {
            return value.clone();
        }
        if self.reset_storage {
            return None;
        }
        Self::get_and_cache_storage(
            &mut self.storage_cache.borrow_mut(),
            &mut self.ownership_cache.borrow_mut(),
            db,
            &self.address,
            key,
        )
        .ok();
        self.ownership_cache
            .borrow()
            .get(key)
            .expect("key exists")
            .clone()
    }

    /// Return the storage change of each related account.
    /// Each account is associated with a pair of `(usize, usize)`. The first
    /// value means the number of keys occupied by this account in current
    /// execution. The second value means the nubmer of keys released by this
    /// account in current execution.
    pub fn commit_ownership_change<'a>(
        &mut self, db: &StateDb<'a>,
    ) -> HashMap<Address, (usize, usize)> {
        let mut storage_delta = HashMap::new();
        let ownership_changes: Vec<_> =
            self.ownership_changes.drain().collect();
        for (k, v) in ownership_changes {
            let cur_value_is_zero = self
                .storage_changes
                .get(&k)
                .expect("key must exists")
                .is_zero();
            let mut ownership_changed = true;
            // Get the owner of `k` before execution. If it is `None`, it means
            // the value of the key is zero before execution. Otherwise, the
            // value of the key is nonzero.
            let original_ownership_opt = self.original_ownership_at(db, &k);
            if let Some(original_ownership) = original_ownership_opt {
                if v == original_ownership {
                    ownership_changed = false;
                }
                // If the current value is zero or the owner has changed for the
                // key, it means the key has released from previous owner.
                if cur_value_is_zero || ownership_changed {
                    storage_delta
                        .entry(original_ownership)
                        .or_insert((0, 0))
                        .1 += 1;
                }
            }
            // If the current value is not zero and the owner has changed, it
            // means the owner has occupied a new key.
            if !cur_value_is_zero && ownership_changed {
                storage_delta.entry(v).or_insert((0, 0)).0 += 1;
            }
            // Commit ownership change to `ownership_cache`.
            if cur_value_is_zero {
                self.ownership_cache.borrow_mut().insert(k, None);
            } else if ownership_changed {
                self.ownership_cache.borrow_mut().insert(k, Some(v));
            }
        }
        storage_delta
    }

    pub fn commit<'a>(&mut self, db: &mut StateDb<'a>) -> DbResult<()> {
        if self.reset_storage {
            db.delete_all(StorageKey::new_storage_root_key(&self.address))?;
            db.delete_all(StorageKey::new_code_root_key(&self.address))?;
            self.reset_storage = false;
        }

        assert!(self.ownership_changes.is_empty());
        let ownership_cache = self.ownership_cache.borrow();
        for (k, v) in self.storage_changes.drain() {
            let address_key =
                StorageKey::new_storage_key(&self.address, k.as_ref());
            let owner = ownership_cache.get(&k).expect("all key must exist");

            match v.is_zero() {
                true => db.delete(address_key)?,
                false => db.set::<StorageValue>(
                    address_key,
                    &StorageValue {
                        value: BigEndianHash::from_uint(&v.into_uint()),
                        owner: owner.expect("owner exists"),
                    },
                )?,
            }
        }
        match self.code() {
            None => {}
            Some(code) => {
                if !code.is_empty() {
                    db.set_raw(
                        StorageKey::new_code_key(
                            &self.address,
                            &self.code_hash,
                        ),
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

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_overlay_account_create() {
        let address = Address::zero();
        let account = Account {
            address,
            balance: 0.into(),
            nonce: 0.into(),
            code_hash: KECCAK_EMPTY,
            bank_balance: 0.into(),
            storage_balance: 0.into(),
            bank_ar: 0.into(),
            deposit_list: Vec::new(),
        };
        // test new from account 1
        let overlay_account = OverlayAccount::new(&address, account, 0.into());
        assert!(overlay_account.deposit_list.is_empty());
        assert_eq!(overlay_account.address, address);
        assert_eq!(overlay_account.balance, 0.into());
        assert_eq!(overlay_account.nonce, 0.into());
        assert_eq!(overlay_account.bank_balance, 0.into());
        assert_eq!(overlay_account.storage_balance, 0.into());
        assert_eq!(overlay_account.bank_ar, 0.into());
        assert_eq!(overlay_account.code_hash, KECCAK_EMPTY);
        assert_eq!(overlay_account.reset_storage, false);
        let account = Account {
            address,
            balance: 101.into(),
            nonce: 55.into(),
            code_hash: KECCAK_EMPTY,
            bank_balance: 11111.into(),
            storage_balance: 455.into(),
            bank_ar: 1.into(),
            deposit_list: Vec::new(),
        };

        // test new from account 2
        let overlay_account = OverlayAccount::new(&address, account, 1.into());
        assert!(overlay_account.deposit_list.is_empty());
        assert_eq!(overlay_account.address, address);
        assert_eq!(overlay_account.balance, 101.into());
        assert_eq!(overlay_account.nonce, 55.into());
        assert_eq!(overlay_account.bank_balance, 11111.into());
        assert_eq!(overlay_account.storage_balance, 455.into());
        assert_eq!(overlay_account.bank_ar, 1.into());
        assert_eq!(overlay_account.code_hash, KECCAK_EMPTY);
        assert_eq!(overlay_account.reset_storage, false);

        // test new basic
        let overlay_account =
            OverlayAccount::new_basic(&address, 1011.into(), 12345.into());
        assert!(overlay_account.deposit_list.is_empty());
        assert_eq!(overlay_account.address, address);
        assert_eq!(overlay_account.balance, 1011.into());
        assert_eq!(overlay_account.nonce, 12345.into());
        assert_eq!(overlay_account.bank_balance, 0.into());
        assert_eq!(overlay_account.storage_balance, 0.into());
        assert_eq!(overlay_account.bank_ar, 0.into());
        assert_eq!(overlay_account.code_hash, KECCAK_EMPTY);
        assert_eq!(overlay_account.reset_storage, false);

        // test new contract
        let overlay_account = OverlayAccount::new_contract(
            &address,
            5678.into(),
            1234.into(),
            true,
        );
        assert!(overlay_account.deposit_list.is_empty());
        assert_eq!(overlay_account.address, address);
        assert_eq!(overlay_account.balance, 5678.into());
        assert_eq!(overlay_account.nonce, 1234.into());
        assert_eq!(overlay_account.bank_balance, 0.into());
        assert_eq!(overlay_account.storage_balance, 0.into());
        assert_eq!(overlay_account.bank_ar, 0.into());
        assert_eq!(overlay_account.code_hash, KECCAK_EMPTY);
        assert_eq!(overlay_account.reset_storage, true);
    }

    #[test]
    fn test_deposit_and_withdraw() {
        let address = Address::zero();
        let account = Account {
            address,
            balance: 0.into(),
            nonce: 0.into(),
            code_hash: KECCAK_EMPTY,
            bank_balance: 0.into(),
            storage_balance: 0.into(),
            bank_ar: 0.into(),
            deposit_list: Vec::new(),
        };
        let mut overlay_account =
            OverlayAccount::new(&address, account, 0.into());
        // add balance
        overlay_account.add_balance(&200000.into());
        assert_eq!(*overlay_account.balance(), U256::from(200000));
        // deposit
        overlay_account.deposit(&100000.into(), 1);
        assert_eq!(*overlay_account.balance(), U256::from(100000));
        overlay_account.deposit(&10000.into(), 2);
        assert_eq!(*overlay_account.balance(), U256::from(90000));
        overlay_account.deposit(&1000.into(), 3);
        assert_eq!(*overlay_account.balance(), U256::from(89000));
        overlay_account.deposit(&100.into(), 4);
        assert_eq!(*overlay_account.balance(), U256::from(88900));
        overlay_account.deposit(&10.into(), 5);
        assert_eq!(*overlay_account.balance(), U256::from(88890));
        overlay_account.deposit(&5.into(), 6);
        assert_eq!(*overlay_account.balance(), U256::from(88885));
        overlay_account.deposit(&1.into(), 7);
        assert_eq!(*overlay_account.balance(), U256::from(88884));
        assert_eq!(overlay_account.deposit_list.len(), 7);
        assert_eq!(*overlay_account.bank_balance(), U256::from(111116));
        assert_eq!(*overlay_account.storage_balance(), U256::from(0));
        // add storage
        overlay_account.add_storage_balance(&11116.into());
        assert_eq!(*overlay_account.storage_balance(), U256::from(11116));
        // do interest settlement
        assert_eq!(overlay_account.bank_ar, U256::from(0));
        overlay_account
            .bank_balance_settlement(U256::from(INTEREST_RATE_SCALE));
        assert_eq!(overlay_account.bank_ar, U256::from(INTEREST_RATE_SCALE));
        assert_eq!(*overlay_account.balance(), U256::from(188884));
        assert_eq!(*overlay_account.bank_balance(), U256::from(111116));
        assert_eq!(*overlay_account.storage_balance(), U256::from(11116));
        // withdraw
        overlay_account.withdraw(&5.into());
        assert_eq!(overlay_account.deposit_list.len(), 6);
        assert_eq!(overlay_account.deposit_list[5].amount, 1.into());
        assert_eq!(*overlay_account.bank_balance(), U256::from(111111));
        assert_eq!(*overlay_account.balance(), U256::from(188889));
        overlay_account.withdraw(&100.into());
        assert_eq!(overlay_account.deposit_list.len(), 4);
        assert_eq!(overlay_account.deposit_list[3].amount, 11.into());
        assert_eq!(*overlay_account.bank_balance(), U256::from(111011));
        assert_eq!(*overlay_account.balance(), U256::from(188989));
    }
}
