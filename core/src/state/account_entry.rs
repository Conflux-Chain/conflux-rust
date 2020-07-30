// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::{Bytes, ToPretty},
    consensus::debug::ComputeEpochDebugRecord,
    hash::{keccak, KECCAK_EMPTY},
    statedb::{Result as DbResult, StateDb},
};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use parking_lot::RwLock;
use primitives::{
    account::AccountError, Account, CodeInfo, DepositInfo, DepositList,
    SponsorInfo, StorageKey, StorageLayout, StorageValue, VoteStakeInfo,
    VoteStakeList,
};
use std::{collections::HashMap, sync::Arc};

lazy_static! {
    static ref SPONSOR_ADDRESS_STORAGE_KEY: Vec<u8> =
        keccak("sponsor_address").as_bytes().to_vec();
    static ref SPONSOR_BALANCE_STORAGE_KEY: Vec<u8> =
        keccak("sponsor_balance").as_bytes().to_vec();
    static ref COMMISSION_PRIVILEGE_STORAGE_VALUE: U256 =
        U256::one();
    /// If we set this key, it means every account has commission privilege.
    static ref COMMISSION_PRIVILEGE_SPECIAL_KEY: Address = Address::zero();
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

    // This is the sponsor information of the contract.
    sponsor_info: SponsorInfo,

    // This is a cache for storage change.
    storage_cache: RwLock<HashMap<Vec<u8>, U256>>,
    storage_changes: HashMap<Vec<u8>, U256>,

    // This is a cache for storage ownership change.
    ownership_cache: RwLock<HashMap<Vec<u8>, Option<Address>>>,
    ownership_changes: HashMap<Vec<u8>, Address>,

    // This is a cache including both the paid collateral and unpaid collateral
    fresh_collateral_for_storage: U256,

    // Storage layout change.
    storage_layout_change: Option<StorageLayout>,

    // This is the number of tokens used in staking.
    staking_balance: U256,
    // This is the number of tokens used as collateral for storage, which will
    // be returned to balance if the storage is released.
    collateral_for_storage: U256,
    // This is the accumulated interest return.
    accumulated_interest_return: U256,
    // This is the list of deposit info, sorted in increasing order of
    // `deposit_time`.
    // If it is not `None`, which means it has been loaded from db.
    deposit_list: Option<DepositList>,
    // This is the list of vote info. The `unlock_block_number` sorted in
    // increasing order and the `amount` is sorted in decreasing order. All
    // the `unlock_block_number` and `amount` is unique in the list.
    // If it is not `None`, which means it has been loaded from db.
    vote_stake_list: Option<VoteStakeList>,

    // Code hash of the account.
    code_hash: H256,
    // Size of the acccount code.
    code_size: Option<usize>,
    // Code cache of the account.
    code_cache: Arc<Bytes>,
    code_owner: Address,

    // This flag indicates whether it is a newly created contract. For such
    // account, we will skip looking data from the disk. This flag will stay
    // true until the contract being committed and cleared from the memory.
    is_newly_created_contract: bool,
}

impl OverlayAccount {
    pub fn new(address: &Address, account: Account) -> Self {
        let overlay_account = OverlayAccount {
            address: address.clone(),
            balance: account.balance,
            nonce: account.nonce,
            admin: account.admin,
            sponsor_info: account.sponsor_info,
            storage_cache: Default::default(),
            storage_changes: HashMap::new(),
            ownership_cache: Default::default(),
            ownership_changes: HashMap::new(),
            storage_layout_change: None,
            staking_balance: account.staking_balance,
            collateral_for_storage: account.collateral_for_storage,
            fresh_collateral_for_storage: account.collateral_for_storage,
            accumulated_interest_return: account.accumulated_interest_return,
            deposit_list: None,
            vote_stake_list: None,
            code_hash: account.code_hash,
            code_size: None,
            code_cache: Arc::new(vec![]),
            code_owner: Address::zero(),
            is_newly_created_contract: false,
        };

        overlay_account
    }

    pub fn new_basic(address: &Address, balance: U256, nonce: U256) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce,
            admin: Address::zero(),
            sponsor_info: Default::default(),
            storage_cache: Default::default(),
            storage_changes: HashMap::new(),
            ownership_cache: Default::default(),
            ownership_changes: HashMap::new(),
            storage_layout_change: None,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            fresh_collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: None,
            vote_stake_list: None,
            code_hash: KECCAK_EMPTY,
            code_size: None,
            code_cache: Arc::new(vec![]),
            code_owner: Address::zero(),
            is_newly_created_contract: false,
        }
    }

    #[cfg(test)]
    pub fn new_contract(address: &Address, balance: U256, nonce: U256) -> Self {
        Self::new_contract_with_admin(address, balance, nonce, &Address::zero())
    }

    pub fn new_contract_with_admin(
        address: &Address, balance: U256, nonce: U256, admin: &Address,
    ) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce,
            admin: admin.clone(),
            sponsor_info: Default::default(),
            storage_cache: Default::default(),
            storage_changes: HashMap::new(),
            ownership_cache: Default::default(),
            ownership_changes: HashMap::new(),
            storage_layout_change: None,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            fresh_collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: None,
            vote_stake_list: None,
            code_hash: KECCAK_EMPTY,
            code_size: None,
            code_cache: Arc::new(Default::default()),
            code_owner: Address::zero(),
            is_newly_created_contract: true,
        }
    }

    pub fn as_account(&self) -> Result<Account, AccountError> {
        let mut account = Account::default();

        account.balance = self.balance;
        account.nonce = self.nonce;
        account.code_hash = self.code_hash;
        account.staking_balance = self.staking_balance;
        account.collateral_for_storage = self.collateral_for_storage;
        assert!(
            self.fresh_collateral_for_storage == self.collateral_for_storage
        );
        account.accumulated_interest_return = self.accumulated_interest_return;
        account.admin = self.admin;
        account.sponsor_info = self.sponsor_info.clone();
        account.set_address(self.address)?;

        Ok(account)
    }

    pub fn is_contract(&self) -> bool { self.address.is_contract_address() }

    pub fn address(&self) -> &Address { &self.address }

    pub fn balance(&self) -> &U256 { &self.balance }

    pub fn sponsor_info(&self) -> &SponsorInfo { &self.sponsor_info }

    pub fn set_sponsor_for_gas(
        &mut self, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    )
    {
        self.sponsor_info.sponsor_for_gas = *sponsor;
        self.sponsor_info.sponsor_balance_for_gas = *sponsor_balance;
        self.sponsor_info.sponsor_gas_bound = *upper_bound;
    }

    pub fn set_sponsor_for_collateral(
        &mut self, sponsor: &Address, sponsor_balance: &U256,
    ) {
        self.sponsor_info.sponsor_for_collateral = *sponsor;
        self.sponsor_info.sponsor_balance_for_collateral = *sponsor_balance;
    }

    pub fn admin(&self) -> &Address { &self.admin }

    pub fn sub_sponsor_balance_for_gas(&mut self, by: &U256) {
        assert!(self.sponsor_info.sponsor_balance_for_gas >= *by);
        self.sponsor_info.sponsor_balance_for_gas -= *by;
    }

    pub fn add_sponsor_balance_for_gas(&mut self, by: &U256) {
        self.sponsor_info.sponsor_balance_for_gas += *by;
    }

    pub fn sub_sponsor_balance_for_collateral(&mut self, by: &U256) {
        assert!(self.sponsor_info.sponsor_balance_for_collateral >= *by);
        self.sponsor_info.sponsor_balance_for_collateral -= *by;
    }

    pub fn add_sponsor_balance_for_collateral(&mut self, by: &U256) {
        self.sponsor_info.sponsor_balance_for_collateral += *by;
    }

    pub fn set_admin(&mut self, requester: &Address, admin: &Address) {
        if self.is_contract() && self.admin == *requester {
            self.admin = admin.clone();
        }
    }

    pub fn register_unrefunded_collateral(&mut self, by: &U256) {
        self.fresh_collateral_for_storage -= *by;
    }

    pub fn register_unpaid_collateral(&mut self, by: &U256) {
        self.fresh_collateral_for_storage += *by;
    }

    pub fn check_commission_privilege(
        &self, db: &StateDb, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        let mut special_key = Vec::with_capacity(Address::len_bytes() * 2);
        special_key.extend_from_slice(contract_address.as_bytes());
        special_key
            .extend_from_slice(COMMISSION_PRIVILEGE_SPECIAL_KEY.as_bytes());
        let special_value = self.storage_at(db, &special_key)?;
        if !special_value.is_zero() {
            Ok(true)
        } else {
            let mut key = Vec::with_capacity(Address::len_bytes() * 2);
            key.extend_from_slice(contract_address.as_bytes());
            key.extend_from_slice(user.as_bytes());
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
        let mut key = Vec::with_capacity(Address::len_bytes() * 2);
        key.extend_from_slice(contract_address.as_bytes());
        key.extend_from_slice(user.as_bytes());
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
        let mut key = Vec::with_capacity(Address::len_bytes() * 2);
        key.extend_from_slice(contract_address.as_bytes());
        key.extend_from_slice(user.as_bytes());
        self.set_storage(key, U256::zero(), contract_owner);
    }

    pub fn staking_balance(&self) -> &U256 { &self.staking_balance }

    pub fn collateral_for_storage(&self) -> &U256 {
        &self.collateral_for_storage
    }

    pub fn fresh_collateral_for_storage(&self) -> &U256 {
        &self.fresh_collateral_for_storage
    }

    #[cfg(test)]
    pub fn accumulated_interest_return(&self) -> &U256 {
        &self.accumulated_interest_return
    }

    pub fn remove_expired_vote_stake_info(&mut self, block_number: u64) {
        assert!(self.vote_stake_list.is_some());
        let vote_stake_list = self.vote_stake_list.as_mut().unwrap();
        if !vote_stake_list.is_empty()
            && vote_stake_list[0].unlock_block_number <= block_number
        {
            // Find first index whose `unlock_block_number` is greater than
            // timestamp and all entries before the index could be
            // removed.
            let idx = vote_stake_list
                .binary_search_by(|vote_info| {
                    vote_info.unlock_block_number.cmp(&(block_number + 1))
                })
                .unwrap_or_else(|x| x);
            *vote_stake_list = VoteStakeList(vote_stake_list.split_off(idx));
        }
    }

    pub fn withdrawable_staking_balance(&self, block_number: u64) -> U256 {
        assert!(self.vote_stake_list.is_some());
        let vote_stake_list = self.vote_stake_list.as_ref().unwrap();
        if !vote_stake_list.is_empty() {
            // Find first index whose `unlock_block_number` is greater than
            // timestamp and all entries before the index could be
            // ignored.
            let idx = vote_stake_list
                .binary_search_by(|vote_info| {
                    vote_info.unlock_block_number.cmp(&(block_number + 1))
                })
                .unwrap_or_else(|x| x);
            if idx == vote_stake_list.len() {
                self.staking_balance
            } else {
                self.staking_balance - vote_stake_list[idx].amount
            }
        } else {
            self.staking_balance
        }
    }

    pub fn deposit_list(&self) -> Option<&DepositList> {
        self.deposit_list.as_ref()
    }

    pub fn vote_stake_list(&self) -> Option<&VoteStakeList> {
        self.vote_stake_list.as_ref()
    }

    #[cfg(test)]
    pub fn storage_changes(&self) -> &HashMap<Vec<u8>, U256> {
        &self.storage_changes
    }

    #[cfg(test)]
    pub fn ownership_changes(&self) -> &HashMap<Vec<u8>, Address> {
        &self.ownership_changes
    }

    #[cfg(test)]
    pub fn is_newly_created_contract(&self) -> bool {
        self.is_newly_created_contract
    }

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

    pub fn set_nonce(&mut self, nonce: &U256) { self.nonce = *nonce; }

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
        assert!(self.deposit_list.is_some());
        self.sub_balance(&amount);
        self.staking_balance += amount;
        self.deposit_list.as_mut().unwrap().push(DepositInfo {
            amount,
            deposit_time,
            accumulated_interest_rate,
        });
    }

    /// Withdraw some amount of tokens, return the value of interest.
    pub fn withdraw(
        &mut self, amount: U256, accumulated_interest_rate: U256,
    ) -> U256 {
        assert!(self.deposit_list.is_some());
        let deposit_list = self.deposit_list.as_mut().unwrap();
        self.staking_balance -= amount;
        let mut rest = amount;
        let mut interest = U256::zero();
        let mut index = 0;
        while !rest.is_zero() {
            let capital = std::cmp::min(deposit_list[index].amount, rest);
            interest += capital * accumulated_interest_rate
                / deposit_list[index].accumulated_interest_rate
                - capital;

            deposit_list[index].amount -= capital;
            rest -= capital;
            if deposit_list[index].amount.is_zero() {
                index += 1;
            }
        }
        if index > 0 {
            *deposit_list = DepositList(deposit_list.split_off(index));
        }
        self.accumulated_interest_return += interest;
        self.add_balance(&(amount + interest));
        interest
    }

    pub fn vote_lock(&mut self, amount: U256, unlock_block_number: u64) {
        assert!(self.vote_stake_list.is_some());
        assert!(amount <= self.staking_balance);
        let vote_stake_list = self.vote_stake_list.as_mut().unwrap();
        let mut updated = false;
        let mut updated_index = 0;
        match vote_stake_list.binary_search_by(|vote_info| {
            vote_info.unlock_block_number.cmp(&unlock_block_number)
        }) {
            Ok(index) => {
                if amount > vote_stake_list[index].amount {
                    vote_stake_list[index].amount = amount;
                    updated = true;
                    updated_index = index;
                }
            }
            Err(index) => {
                if index >= vote_stake_list.len()
                    || vote_stake_list[index].amount < amount
                {
                    vote_stake_list.insert(
                        index,
                        VoteStakeInfo {
                            amount,
                            unlock_block_number,
                        },
                    );
                    updated = true;
                    updated_index = index;
                }
            }
        }
        if updated {
            let rest = vote_stake_list.split_off(updated_index);
            while !vote_stake_list.is_empty()
                && vote_stake_list.last().unwrap().amount <= rest[0].amount
            {
                vote_stake_list.pop();
            }
            vote_stake_list.extend_from_slice(&rest);
        }
    }

    pub fn add_collateral_for_storage(&mut self, by: &U256) {
        if self.is_contract() {
            self.sub_sponsor_balance_for_collateral(by);
        } else {
            self.sub_balance(by);
        }
        self.collateral_for_storage += *by;
    }

    pub fn sub_collateral_for_storage(&mut self, by: &U256) {
        assert!(self.collateral_for_storage >= *by);
        if self.is_contract() {
            self.add_sponsor_balance_for_collateral(by);
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

    pub fn cache_staking_info(
        &mut self, cache_deposit_list: bool, cache_vote_list: bool,
        db: &StateDb,
    ) -> DbResult<()>
    {
        if cache_deposit_list && self.deposit_list.is_none() {
            let deposit_list_opt = db.get_deposit_list(&self.address)?;
            self.deposit_list = Some(deposit_list_opt.unwrap_or_default());
        }
        if cache_vote_list && self.vote_stake_list.is_none() {
            let vote_list_opt = db.get_vote_list(&self.address)?;
            self.vote_stake_list = Some(vote_list_opt.unwrap_or_default());
        }
        Ok(())
    }

    pub fn clone_basic(&self) -> Self {
        OverlayAccount {
            address: self.address,
            balance: self.balance,
            nonce: self.nonce,
            admin: self.admin,
            sponsor_info: self.sponsor_info.clone(),
            storage_cache: Default::default(),
            storage_changes: HashMap::new(),
            ownership_cache: Default::default(),
            ownership_changes: HashMap::new(),
            storage_layout_change: None,
            staking_balance: self.staking_balance,
            collateral_for_storage: self.collateral_for_storage,
            fresh_collateral_for_storage: self.fresh_collateral_for_storage,
            accumulated_interest_return: self.accumulated_interest_return,
            deposit_list: self.deposit_list.clone(),
            vote_stake_list: self.vote_stake_list.clone(),
            code_hash: self.code_hash,
            code_size: self.code_size,
            code_cache: self.code_cache.clone(),
            code_owner: self.code_owner,
            is_newly_created_contract: self.is_newly_created_contract,
        }
    }

    pub fn clone_dirty(&self) -> Self {
        let mut account = self.clone_basic();
        account.storage_changes = self.storage_changes.clone();
        account.storage_cache = RwLock::new(self.storage_cache.read().clone());
        account.ownership_cache =
            RwLock::new(self.ownership_cache.read().clone());
        account.ownership_changes = self.ownership_changes.clone();
        account.storage_layout_change = self.storage_layout_change.clone();
        account
    }

    pub fn set_storage(&mut self, key: Vec<u8>, value: U256, owner: Address) {
        self.storage_changes.insert(key.clone(), value);
        self.ownership_changes.insert(key, owner);
    }

    pub fn set_storage_layout(&mut self, layout: StorageLayout) {
        self.storage_layout_change = Some(layout);
    }

    pub fn cached_storage_at(&self, key: &Vec<u8>) -> Option<U256> {
        if let Some(value) = self.storage_changes.get(key) {
            return Some(value.clone());
        }
        if let Some(value) = self.storage_cache.read().get(key) {
            return Some(value.clone());
        }
        None
    }

    pub fn storage_at(&self, db: &StateDb, key: &Vec<u8>) -> DbResult<U256> {
        if let Some(value) = self.cached_storage_at(key) {
            return Ok(value);
        }
        if self.is_newly_created_contract {
            Ok(U256::zero())
        } else {
            Self::get_and_cache_storage(
                &mut self.storage_cache.write(),
                &mut self.ownership_cache.write(),
                db,
                &self.address,
                key,
                true, /* cache_ownership */
            )
        }
    }

    fn get_and_cache_storage(
        storage_cache: &mut HashMap<Vec<u8>, U256>,
        ownership_cache: &mut HashMap<Vec<u8>, Option<Address>>, db: &StateDb,
        address: &Address, key: &Vec<u8>, cache_ownership: bool,
    ) -> DbResult<U256>
    {
        assert!(!ownership_cache.contains_key(key));
        if let Some(value) = db.get::<StorageValue>(
            StorageKey::new_storage_key(address, key.as_ref()),
        )? {
            storage_cache.insert(key.clone(), value.value);
            if cache_ownership {
                ownership_cache.insert(
                    key.clone(),
                    Some(match value.owner {
                        Some(owner) => owner,
                        None => *address,
                    }),
                );
            }
            Ok(value.value)
        } else {
            storage_cache.insert(key.clone(), U256::zero());
            if cache_ownership {
                ownership_cache.insert(key.clone(), None);
            }
            Ok(U256::zero())
        }
    }

    pub fn init_code(&mut self, code: Bytes, owner: Address) {
        self.code_hash = keccak(&code);
        self.code_cache = Arc::new(code);
        self.code_owner = owner;
        self.code_size = Some(self.code_cache.len());
    }

    pub fn overwrite_with(&mut self, other: OverlayAccount) {
        self.balance = other.balance;
        self.nonce = other.nonce;
        self.admin = other.admin;
        self.sponsor_info = other.sponsor_info;
        self.code_hash = other.code_hash;
        self.code_cache = other.code_cache;
        self.code_owner = other.code_owner;
        self.code_size = other.code_size;
        self.storage_cache = other.storage_cache;
        self.storage_changes = other.storage_changes;
        self.ownership_cache = other.ownership_cache;
        self.ownership_changes = other.ownership_changes;
        self.storage_layout_change = other.storage_layout_change;
        self.staking_balance = other.staking_balance;
        self.collateral_for_storage = other.collateral_for_storage;
        self.fresh_collateral_for_storage = other.fresh_collateral_for_storage;
        self.accumulated_interest_return = other.accumulated_interest_return;
        self.deposit_list = other.deposit_list;
        self.vote_stake_list = other.vote_stake_list;
        self.is_newly_created_contract = other.is_newly_created_contract;
    }

    /// Return the owner of `key` before this execution. If it is `None`, it
    /// means the value of the key is zero before this execution. Otherwise, the
    /// value of the key is nonzero.
    fn original_ownership_at(
        &self, db: &StateDb, key: &Vec<u8>,
    ) -> DbResult<Option<Address>> {
        if let Some(value) = self.ownership_cache.read().get(key) {
            return Ok(value.clone());
        }
        if self.is_newly_created_contract {
            return Ok(None);
        }
        let ownership_cache = &mut *self.ownership_cache.write();
        Self::get_and_cache_storage(
            &mut self.storage_cache.write(),
            ownership_cache,
            db,
            &self.address,
            key,
            true, /* cache_ownership */
        )?;
        Ok(ownership_cache.get(key).expect("key exists").clone())
    }

    /// Return the storage change of each related account.
    /// Each account is associated with a pair of `(usize, usize)`. The first
    /// value means the number of keys occupied by this account in current
    /// execution. The second value means the number of keys released by this
    /// account in current execution.
    pub fn commit_ownership_change(
        &mut self, db: &StateDb,
    ) -> DbResult<HashMap<Address, (u64, u64)>> {
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
            let original_ownership_opt = self.original_ownership_at(db, &k)?;
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
                self.ownership_cache.get_mut().insert(k, None);
            } else if ownership_changed {
                self.ownership_cache.get_mut().insert(k, Some(v));
            }
        }
        assert!(self.ownership_changes.is_empty());
        Ok(storage_delta)
    }

    pub fn commit(
        &mut self, db: &mut StateDb,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        // reinsert storage_layout to delta trie if storage is updated
        // FIXME: load storage layout on first storage access instead
        if !self.storage_changes.is_empty()
            && self.storage_layout_change.is_none()
        {
            // try to get from delta tries or snapshot
            let layout = db
                .get_storage_layout(&self.address)?
                // layout must exist for existing accounts
                // storage_layout_change cannot be None for new accounts
                .expect("storage layout should exist");

            db.set_storage_layout(
                &self.address,
                &layout,
                debug_record.as_deref_mut(),
            )?;
        }

        assert!(self.ownership_changes.is_empty());
        let ownership_cache = self.ownership_cache.get_mut();
        for (k, v) in self.storage_changes.drain() {
            let address_key =
                StorageKey::new_storage_key(&self.address, k.as_ref());
            match v.is_zero() {
                true => db.delete(address_key, debug_record.as_deref_mut())?,
                false => {
                    let owner = ownership_cache
                        .get(&k)
                        .expect("all key must exist")
                        .expect("owner exists");

                    db.set::<StorageValue>(
                        address_key,
                        &StorageValue {
                            value: v,
                            owner: if owner == self.address {
                                None
                            } else {
                                Some(owner)
                            },
                        },
                        debug_record.as_deref_mut(),
                    )?
                }
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
                        debug_record.as_deref_mut(),
                    )?;
                }
            }
        }

        match self.deposit_list.as_ref() {
            None => {}
            Some(deposit_list) => {
                let storage_key =
                    StorageKey::new_deposit_list_key(&self.address);
                if deposit_list.is_empty() {
                    db.delete(storage_key, debug_record.as_deref_mut())?;
                } else {
                    db.set::<DepositList>(
                        storage_key,
                        deposit_list,
                        debug_record.as_deref_mut(),
                    )?;
                }
            }
        }

        match self.vote_stake_list.as_ref() {
            None => {}
            Some(vote_stake_list) => {
                let storage_key = StorageKey::new_vote_list_key(&self.address);
                if vote_stake_list.is_empty() {
                    db.delete(storage_key, debug_record.as_deref_mut())?;
                } else {
                    db.set::<VoteStakeList>(
                        storage_key,
                        vote_stake_list,
                        debug_record.as_deref_mut(),
                    )?;
                }
            }
        }

        if let Some(ref layout) = self.storage_layout_change {
            db.set_storage_layout(&self.address, layout, debug_record)?;
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
    /// Account proxy. `None` if account known to be non-existent.
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
