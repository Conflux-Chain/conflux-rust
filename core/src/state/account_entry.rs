// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::{Bytes, ToPretty},
    hash::{keccak, KECCAK_EMPTY},
    parameters::staking::*,
    statedb::{Result as DbResult, StateDb},
};
use cfx_types::{Address, BigEndianHash, H256, U256};
use primitives::{Account, CodeInfo, DepositInfo, StakingVoteInfo, StorageKey};
use rlp::RlpStream;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{cell::RefCell, collections::HashMap, sync::Arc};

lazy_static! {
    static ref SPONSOR_ADDRESS_STORAGE_KEY: H256 =
        keccak("sponsor_address");
    static ref SPONSOR_BALANCE_STORAGE_KEY: H256 =
        keccak("sponsor_balance");
    static ref COMMISSION_PRIVILEGE_STORAGE_VALUE: H256 =
        H256::from_low_u64_le(1);
    /// If we set this key, it means every account has commission privilege.
    static ref COMMISSION_PRIVILEGE_SPECIAL_KEY: Address = Address::zero();
}

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

    // Balance of the account.
    balance: U256,
    // Nonce of the account,
    nonce: U256,

    // Administrator of the account
    admin: Address,

    // This is the address of the sponsor of the contract.
    sponsor: Address,
    // This is the amount of tokens sponsor to the contract.
    sponsor_balance: U256,

    // This is a cache for storage change.
    storage_cache: RefCell<HashMap<H256, H256>>,
    storage_changes: HashMap<H256, H256>,
    // This is a cache for storage ownership change.
    ownership_cache: RefCell<HashMap<H256, Option<Address>>>,
    ownership_changes: HashMap<H256, Address>,

    // This is the number of tokens used in staking.
    staking_balance: U256,
    // This is the number of tokens can be withdrawed.
    withdrawable_staking_balance: U256,
    // This is the number of tokens used as collateral for storage, which will
    // be returned to balance if the storage is released.
    collateral_for_storage: U256,
    // This is the accumulated interest return.
    accumulated_interest_return: U256,
    // This is the list of deposit info, sorted in increasing order of
    // `deposit_time`.
    deposit_list: Vec<DepositInfo>,
    // This is the list of vote info. The `unlock_time` sorted in increasing
    // order and the `amount` is sorted in decreasing order. All the
    // `unlock_time` and `amount` is unique in the list.
    staking_vote_list: Vec<StakingVoteInfo>,

    // Code hash of the account.
    code_hash: H256,
    // Size of the acccount code.
    code_size: Option<usize>,
    // Code cache of the account.
    code_cache: Arc<Bytes>,
    code_owner: Address,

    reset_storage: bool,
    // Whether it is a contract address.
    is_contract: bool,
}

impl OverlayAccount {
    pub fn new(address: &Address, account: Account, timestamp: u64) -> Self {
        let mut overlay_account = OverlayAccount {
            address: address.clone(),
            balance: account.balance,
            nonce: account.nonce,
            admin: account.admin,
            sponsor: account.sponsor,
            sponsor_balance: account.sponsor_balance,
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            staking_balance: account.staking_balance,
            withdrawable_staking_balance: 0.into(),
            collateral_for_storage: account.collateral_for_storage,
            accumulated_interest_return: account.accumulated_interest_return,
            deposit_list: account.deposit_list.clone(),
            staking_vote_list: account.staking_vote_list.clone(),
            code_hash: account.code_hash,
            code_size: None,
            code_cache: Arc::new(vec![]),
            code_owner: Address::zero(),
            reset_storage: false,
            is_contract: account.code_hash != KECCAK_EMPTY,
        };

        if !overlay_account.staking_vote_list.is_empty()
            && overlay_account.staking_vote_list[0].unlock_time <= timestamp
        {
            // Find first index whose `unlock_time` is greater than timestamp
            // and all entries before the index could be removed.
            let idx = overlay_account
                .staking_vote_list
                .binary_search_by(|vote_info| {
                    vote_info.unlock_time.cmp(&(timestamp + 1))
                })
                .unwrap_or_else(|x| x);
            overlay_account.staking_vote_list =
                overlay_account.staking_vote_list.split_off(idx);
        }
        overlay_account.withdrawable_staking_balance =
            if overlay_account.staking_vote_list.is_empty() {
                overlay_account.staking_balance
            } else {
                overlay_account.staking_balance
                    - overlay_account.staking_vote_list[0].amount
            };

        overlay_account
    }

    pub fn new_basic(address: &Address, balance: U256, nonce: U256) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce,
            admin: Address::zero(),
            sponsor: Address::zero(),
            sponsor_balance: U256::zero(),
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            staking_balance: 0.into(),
            withdrawable_staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: Vec::new(),
            staking_vote_list: Vec::new(),
            code_hash: KECCAK_EMPTY,
            code_size: None,
            code_cache: Arc::new(vec![]),
            code_owner: Address::zero(),
            reset_storage: false,
            is_contract: false,
        }
    }

    pub fn new_contract(
        address: &Address, balance: U256, nonce: U256, reset_storage: bool,
    ) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce,
            admin: Address::zero(),
            sponsor: Address::zero(),
            sponsor_balance: U256::zero(),
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            staking_balance: 0.into(),
            withdrawable_staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: Vec::new(),
            staking_vote_list: Vec::new(),
            code_hash: KECCAK_EMPTY,
            code_size: None,
            code_cache: Arc::new(vec![]),
            code_owner: Address::zero(),
            reset_storage,
            is_contract: true,
        }
    }

    pub fn new_contract_with_admin(
        address: &Address, balance: U256, nonce: U256, reset_storage: bool,
        admin: &Address,
    ) -> Self
    {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce,
            admin: admin.clone(),
            sponsor: Address::zero(),
            sponsor_balance: U256::zero(),
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            staking_balance: 0.into(),
            withdrawable_staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: Vec::new(),
            staking_vote_list: Vec::new(),
            code_hash: KECCAK_EMPTY,
            code_size: None,
            code_cache: Arc::new(Default::default()),
            code_owner: Address::zero(),
            reset_storage,
            is_contract: true,
        }
    }

    pub fn as_account(&self) -> Account {
        Account {
            address: self.address,
            balance: self.balance,
            nonce: self.nonce,
            code_hash: self.code_hash,
            staking_balance: self.staking_balance,
            collateral_for_storage: self.collateral_for_storage,
            accumulated_interest_return: self.accumulated_interest_return,
            deposit_list: self.deposit_list.clone(),
            staking_vote_list: self.staking_vote_list.clone(),
            admin: self.admin,
            sponsor: self.sponsor,
            sponsor_balance: self.sponsor_balance,
        }
    }

    pub fn is_contract(&self) -> bool { self.is_contract }

    pub fn address(&self) -> &Address { &self.address }

    pub fn balance(&self) -> &U256 { &self.balance }

    pub fn sponsor_balance(&self) -> &U256 { &self.sponsor_balance }

    pub fn set_sponsor(&mut self, sponsor: Address, sponsor_balance: U256) {
        self.sponsor = sponsor;
        self.sponsor_balance = sponsor_balance;
    }

    pub fn sponsor(&self) -> &Address { &self.sponsor }

    #[cfg(test)]
    pub fn admin(&self) -> &Address { &self.admin }

    pub fn sub_sponsor_balance(&mut self, by: &U256) {
        assert!(self.sponsor_balance >= *by);
        self.sponsor_balance -= *by;
    }

    pub fn add_sponsor_balance(&mut self, by: &U256) {
        self.sponsor_balance += *by;
    }

    pub fn set_admin(&mut self, requester: &Address, admin: &Address) {
        if self.is_contract {
            if self.admin.is_zero() || self.admin == *requester {
                self.admin = admin.clone();
            }
        }
    }

    pub fn check_commission_privilege(
        &self, db: &StateDb, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        let special_key = {
            let mut rlp_stream = RlpStream::new_list(2);
            rlp_stream.append_list(contract_address.as_ref());
            rlp_stream.append_list(COMMISSION_PRIVILEGE_SPECIAL_KEY.as_ref());
            keccak(rlp_stream.out())
        };
        let special_value = self.storage_at(db, &special_key)?;
        if !special_value.is_zero() {
            Ok(true)
        } else {
            let key = {
                let mut rlp_stream = RlpStream::new_list(2);
                rlp_stream.append_list(contract_address.as_ref());
                rlp_stream.append_list(user.as_ref());
                keccak(rlp_stream.out())
            };
            self.storage_at(db, &key).map(|x| !x.is_zero())
        }
    }

    /// Add commission privilege of `contract_address` to `user`.
    /// We set the value to some nonzero value which will be persisted in db.
    pub fn add_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    )
    {
        let mut rlp_stream = RlpStream::new_list(2);
        rlp_stream.append_list(contract_address.as_ref());
        rlp_stream.append_list(user.as_ref());
        let key = keccak(rlp_stream.out());
        self.set_storage(
            key,
            COMMISSION_PRIVILEGE_STORAGE_VALUE.clone(),
            contract_owner,
        );
    }

    /// Remove commission privilege of `contract_address` from `user`.
    /// We set the value to zero, and the key/value will be released at commit
    /// phase.
    pub fn remove_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    )
    {
        let mut rlp_stream = RlpStream::new_list(2);
        rlp_stream.append_list(contract_address.as_ref());
        rlp_stream.append_list(user.as_ref());
        let key = keccak(rlp_stream.out());
        self.set_storage(key, H256::zero(), contract_owner);
    }

    pub fn staking_balance(&self) -> &U256 { &self.staking_balance }

    pub fn collateral_for_storage(&self) -> &U256 {
        &self.collateral_for_storage
    }

    #[cfg(test)]
    pub fn accumulated_interest_return(&self) -> &U256 {
        &self.accumulated_interest_return
    }

    pub fn withdrawable_staking_balance(&self) -> &U256 {
        &self.withdrawable_staking_balance
    }

    #[cfg(test)]
    pub fn deposit_list(&self) -> &Vec<DepositInfo> { &self.deposit_list }

    #[cfg(test)]
    pub fn staking_vote_list(&self) -> &Vec<StakingVoteInfo> {
        &self.staking_vote_list
    }

    #[cfg(test)]
    pub fn storage_changes(&self) -> &HashMap<H256, H256> {
        &self.storage_changes
    }

    #[cfg(test)]
    pub fn ownership_changes(&self) -> &HashMap<H256, Address> {
        &self.ownership_changes
    }

    #[cfg(test)]
    pub fn reset_storage(&self) -> bool { self.reset_storage }

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

    pub fn code_owner(&self) -> Option<Address> {
        if self.code_hash != KECCAK_EMPTY && self.code_cache.is_empty() {
            None
        } else {
            Some(self.code_owner)
        }
    }

    pub fn is_cached(&self) -> bool {
        !self.code_cache.is_empty()
            || (self.code_cache.is_empty() && self.code_hash == KECCAK_EMPTY)
    }

    pub fn is_null(&self) -> bool {
        self.balance.is_zero()
            && self.staking_balance.is_zero()
            && self.collateral_for_storage.is_zero()
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

    pub fn deposit(
        &mut self, amount: U256, accumulated_interest_rate: U256,
        deposit_time: u64,
    )
    {
        self.sub_balance(&amount);
        self.staking_balance += amount;
        self.withdrawable_staking_balance += amount;
        self.deposit_list.push(DepositInfo {
            amount,
            deposit_time,
            accumulated_interest_rate,
        });
    }

    pub fn withdraw(
        &mut self, amount: U256, accumulated_interest_rate: U256,
        withdraw_time: u64,
    ) -> (U256, U256)
    {
        assert!(self.withdrawable_staking_balance >= amount);
        self.withdrawable_staking_balance -= amount;
        self.staking_balance -= amount;
        let mut rest = amount;
        let mut interest = U256::zero();
        let mut service_charge = U256::zero();
        let mut index = 0;
        while !rest.is_zero() {
            let duration =
                withdraw_time - self.deposit_list[index].deposit_time;
            let interest_rate = accumulated_interest_rate
                - self.deposit_list[index].accumulated_interest_rate;
            let capital = std::cmp::min(self.deposit_list[index].amount, rest);
            interest += capital * interest_rate / *INTEREST_RATE_SCALE;
            if duration < BLOCKS_PER_YEAR {
                service_charge += capital
                    * U256::from(BLOCKS_PER_YEAR - duration)
                    * *SERVICE_CHARGE_RATE
                    / *SERVICE_CHARGE_RATE_SCALE
                    / U256::from(BLOCKS_PER_YEAR);
            }

            self.deposit_list[index].amount -= capital;
            rest -= capital;
            if self.deposit_list[index].amount.is_zero() {
                index += 1;
            }
        }
        if index > 0 {
            self.deposit_list = self.deposit_list.split_off(index);
        }
        self.accumulated_interest_return += interest;
        self.add_balance(&(amount + interest - service_charge));
        (interest, service_charge)
    }

    pub fn lock(&mut self, amount: U256, unlock_time: u64) {
        assert!(amount <= self.staking_balance);
        let mut updated = false;
        let mut updated_index = 0;
        match self.staking_vote_list.binary_search_by(|vote_info| {
            vote_info.unlock_time.cmp(&unlock_time)
        }) {
            Ok(index) => {
                if amount > self.staking_vote_list[index].amount {
                    self.staking_vote_list[index].amount = amount;
                    updated = true;
                    updated_index = index;
                }
            }
            Err(index) => {
                if index >= self.staking_vote_list.len()
                    || self.staking_vote_list[index].amount < amount
                {
                    self.staking_vote_list.insert(
                        index,
                        StakingVoteInfo {
                            amount,
                            unlock_time,
                        },
                    );
                    updated = true;
                    updated_index = index;
                }
            }
        }
        if updated {
            let rest = self.staking_vote_list.split_off(updated_index);
            while !self.staking_vote_list.is_empty()
                && self.staking_vote_list.last().unwrap().amount
                    <= rest[0].amount
            {
                self.staking_vote_list.pop();
            }
            self.staking_vote_list.extend_from_slice(&rest);
        }

        self.withdrawable_staking_balance =
            self.staking_balance - self.staking_vote_list[0].amount;
    }

    pub fn add_collateral_for_storage(&mut self, by: &U256) {
        if self.is_contract {
            self.sub_sponsor_balance(by);
        } else {
            self.sub_balance(by);
        }
        self.collateral_for_storage += *by;
    }

    pub fn sub_collateral_for_storage(&mut self, by: &U256) {
        assert!(self.collateral_for_storage >= *by);
        if self.is_contract {
            self.add_sponsor_balance(by);
        } else {
            self.add_balance(by);
        }
        self.collateral_for_storage -= *by;
    }

    pub fn cache_code(&mut self, db: &StateDb) -> Option<Arc<Bytes>> {
        trace!("OverlayAccount::cache_code: ic={}; self.code_hash={:?}, self.code_cache={}", self.is_cached(), self.code_hash, self.code_cache.pretty());

        if self.is_cached() {
            return Some(self.code_cache.clone());
        }

        match db.get_code(&self.address, &self.code_hash) {
            Ok(Some(code)) => {
                self.code_size = Some(code.code.len());
                self.code_cache = Arc::new(code.code.to_vec());
                self.code_owner = code.owner;
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
            admin: self.admin,
            sponsor: self.sponsor,
            sponsor_balance: self.sponsor_balance,
            storage_cache: RefCell::new(HashMap::new()),
            storage_changes: HashMap::new(),
            ownership_cache: RefCell::new(HashMap::new()),
            ownership_changes: HashMap::new(),
            staking_balance: self.staking_balance,
            withdrawable_staking_balance: self.withdrawable_staking_balance,
            collateral_for_storage: self.collateral_for_storage,
            accumulated_interest_return: self.accumulated_interest_return,
            deposit_list: self.deposit_list.clone(),
            staking_vote_list: self.staking_vote_list.clone(),
            code_hash: self.code_hash,
            code_size: self.code_size,
            code_cache: self.code_cache.clone(),
            code_owner: self.code_owner,
            reset_storage: self.reset_storage,
            is_contract: self.is_contract,
        }
    }

    pub fn clone_dirty(&self) -> Self {
        let mut account = self.clone_basic();
        account.storage_changes = self.storage_changes.clone();
        account.storage_cache = self.storage_cache.clone();
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

    pub fn storage_at(&self, db: &StateDb, key: &H256) -> DbResult<H256> {
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
                true, /* cache_ownership */
            )
        }
    }

    #[cfg(test)]
    pub fn original_storage_at(
        &self, db: &StateDb, key: &H256,
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
            false, /* cache_ownership */
        )
    }

    fn get_and_cache_storage(
        storage_cache: &mut HashMap<H256, H256>,
        ownership_cache: &mut HashMap<H256, Option<Address>>, db: &StateDb,
        address: &Address, key: &H256, cache_ownership: bool,
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
            if cache_ownership {
                ownership_cache.insert(*key, Some(value.owner));
            }
            Ok(value.value)
        } else {
            storage_cache.insert(key.clone(), H256::zero());
            if cache_ownership {
                ownership_cache.insert(*key, None);
            }
            Ok(H256::zero())
        }
    }

    pub fn init_code(&mut self, code: Bytes, owner: Address) {
        self.code_hash = keccak(&code);
        self.code_cache = Arc::new(code);
        self.code_owner = owner;
        self.code_size = Some(self.code_cache.len());
        self.is_contract = true;
    }

    pub fn overwrite_with(&mut self, other: OverlayAccount) {
        self.balance = other.balance;
        self.nonce = other.nonce;
        self.admin = other.admin;
        self.sponsor = other.sponsor;
        self.sponsor_balance = other.sponsor_balance;
        self.code_hash = other.code_hash;
        self.code_cache = other.code_cache;
        self.code_owner = other.code_owner;
        self.code_size = other.code_size;
        self.storage_cache = other.storage_cache;
        self.storage_changes = other.storage_changes;
        self.ownership_cache = other.ownership_cache;
        self.ownership_changes = other.ownership_changes;
        self.staking_balance = other.staking_balance;
        self.withdrawable_staking_balance = other.withdrawable_staking_balance;
        self.collateral_for_storage = other.collateral_for_storage;
        self.accumulated_interest_return = other.accumulated_interest_return;
        self.deposit_list = other.deposit_list;
        self.staking_vote_list = other.staking_vote_list;
        self.reset_storage = other.reset_storage;
        self.is_contract = other.is_contract;
    }

    /// Return the owner of `key` before this execution. If it is `None`, it
    /// means the value of the key is zero before this execution. Otherwise, the
    /// value of the key is nonzero.
    fn original_ownership_at(
        &self, db: &StateDb, key: &H256,
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
            true, /* cache_ownership */
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
    pub fn commit_ownership_change(
        &mut self, db: &StateDb,
    ) -> HashMap<Address, (u64, u64)> {
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
        assert!(self.ownership_changes.is_empty());
        storage_delta
    }

    pub fn commit(&mut self, db: &mut StateDb) -> DbResult<()> {
        if self.reset_storage {
            // FIXME: We should consider ownership reset during storage reset.
            // FIXME: In current implementation, storage reset will only happen
            // FIXME: on contract creation. And in this case, the storage in
            // FIXME: disk should be empty. So we should not worry too much now.
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
                    let storage_key = StorageKey::new_code_key(
                        &self.address,
                        &self.code_hash,
                    );
                    db.set::<CodeInfo>(
                        storage_key,
                        &CodeInfo {
                            code: (*code).clone(),
                            owner: self.code_owner,
                        },
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
