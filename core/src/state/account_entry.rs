// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::Bytes,
    hash::{keccak, KECCAK_EMPTY},
    state::{AccountEntryProtectedMethods, State},
};
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::{
    consensus::ONE_CFX_IN_DRIP,
    internal_contract_addresses::SYSTEM_STORAGE_ADDRESS,
    staking::COLLATERAL_UNITS_PER_STORAGE_KEY,
};
use cfx_statedb::{Result as DbResult, StateDbExt, StateDbGeneric};
#[cfg(test)]
use cfx_types::AddressSpaceUtil;
use cfx_types::{
    address_util::AddressUtil, Address, AddressWithSpace, Space, H256, U256,
};
use parking_lot::RwLock;
use primitives::{
    account::StoragePoints, is_default::IsDefault, Account, CodeInfo,
    DepositInfo, DepositList, SponsorInfo, StorageKey, StorageLayout,
    StorageValue, VoteStakeList,
};
use std::{collections::HashMap, sync::Arc};

use super::Substate;

lazy_static! {
    static ref COMMISSION_PRIVILEGE_STORAGE_VALUE: U256 = U256::one();
    /// If we set this key, it means every account has commission privilege.
    pub static ref COMMISSION_PRIVILEGE_SPECIAL_KEY: Address = Address::zero();
}

#[derive(Debug)]
/// Single account in the system.
/// Keeps track of changes to the code and storage.
/// The changes are applied in `commit_storage` and `commit_code`
pub struct OverlayAccount {
    address: AddressWithSpace,

    // Balance of the account.
    balance: U256,
    // Nonce of the account,
    nonce: U256,

    // Administrator of the account
    admin: Address,

    // This is the sponsor information of the contract.
    sponsor_info: SponsorInfo,

    // FIXME: there are changes, so no need to have cache for both storage and
    // ownership

    // This is a read cache for storage values of the current account in db.
    // The underlying db will not change while computing transactions in an
    // epoch. So all the contents in the read cache is always available.
    storage_value_read_cache: Arc<RwLock<HashMap<Vec<u8>, U256>>>,
    // This is a write cache for changing storage value in db. It will be
    // written to db when committing overlay account.
    storage_value_write_cache: Arc<HashMap<Vec<u8>, U256>>,

    // This is a level 2 cache for storage ownership change of the current
    // account. It will be written to db when committing overlay account.
    //
    // This cache contains intermediate result during transaction execution, it
    // should never be shared among multiple threads. But we also need RwLock
    // here because current implementation requires OverlayAccount: Send +
    // Sync.
    storage_owner_lv2_write_cache:
        RwLock<Arc<HashMap<Vec<u8>, Option<Address>>>>,
    // This is a level 1 cache for storage ownership change of the current
    // account. It will be updated when executing EVM or calling
    // `set_storage` function. It will be merged to level 2 cache at the
    // end of message call or calling `collect_commit_changes`.
    //
    // This maintains the current owner of a
    // specific key. If the owner is `None`, the value of current key is
    // zero.
    storage_owner_lv1_write_cache: Arc<HashMap<Vec<u8>, Option<Address>>>,

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
    // When code_hash isn't KECCAK_EMPTY, the code has been initialized for
    // the account. The code field can be None, which means that the code
    // has not been loaded from storage. When code_hash is KECCAK_EMPTY, this
    // field always None.
    code: Option<CodeInfo>,

    // This flag indicates whether it is a newly created contract. For such
    // account, we will skip looking data from the disk. This flag will stay
    // true until the contract being committed and cleared from the memory.
    //
    // If the contract account at the same address is killed, then the same
    // account is re-created, this flag is also true, to indicate that any
    // pending cleanups must be done. The re-creation of the account can
    // also be caused by a simple payment transaction, which result into a new
    // basic account at the same address.
    is_newly_created_contract: bool,
    invalidated_storage: bool,
}

impl OverlayAccount {
    /// Create an OverlayAccount from loaded account.
    pub fn from_loaded(address: &AddressWithSpace, account: Account) -> Self {
        let overlay_account = OverlayAccount {
            address: address.clone(),
            balance: account.balance,
            nonce: account.nonce,
            admin: account.admin,
            sponsor_info: account.sponsor_info,
            storage_value_read_cache: Default::default(),
            storage_value_write_cache: Default::default(),
            storage_owner_lv2_write_cache: Default::default(),
            storage_owner_lv1_write_cache: Default::default(),
            storage_layout_change: None,
            staking_balance: account.staking_balance,
            collateral_for_storage: account.collateral_for_storage,
            accumulated_interest_return: account.accumulated_interest_return,
            deposit_list: None,
            vote_stake_list: None,
            code_hash: account.code_hash,
            code: None,
            is_newly_created_contract: false,
            invalidated_storage: false,
        };

        overlay_account
    }

    /// Create an OverlayAccount of basic account when the account doesn't exist
    /// before.
    pub fn new_basic(address: &AddressWithSpace, balance: U256) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce: U256::zero(),
            admin: Address::zero(),
            sponsor_info: Default::default(),
            storage_value_read_cache: Default::default(),
            storage_value_write_cache: Default::default(),
            storage_owner_lv2_write_cache: Default::default(),
            storage_owner_lv1_write_cache: Default::default(),
            storage_layout_change: None,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: None,
            vote_stake_list: None,
            code_hash: KECCAK_EMPTY,
            code: None,
            is_newly_created_contract: false,
            invalidated_storage: false,
        }
    }

    /// Create an OverlayAccount of basic account when the account doesn't exist
    /// before.
    pub fn new_removed(address: &AddressWithSpace) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance: Default::default(),
            nonce: Default::default(),
            admin: Address::zero(),
            sponsor_info: Default::default(),
            storage_value_read_cache: Default::default(),
            storage_value_write_cache: Default::default(),
            storage_owner_lv2_write_cache: Default::default(),
            storage_owner_lv1_write_cache: Default::default(),
            storage_layout_change: None,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: None,
            vote_stake_list: None,
            code_hash: KECCAK_EMPTY,
            code: None,
            is_newly_created_contract: false,
            invalidated_storage: true,
        }
    }

    /// Create an OverlayAccount of contract account when the account doesn't
    /// exist before.
    #[cfg(test)]
    pub fn new_contract(
        address: &Address, balance: U256, invalidated_storage: bool,
        storage_layout: Option<StorageLayout>,
    ) -> Self
    {
        Self::new_contract_with_admin(
            &address.with_native_space(),
            balance,
            &Address::zero(),
            invalidated_storage,
            storage_layout,
            false,
        )
    }

    /// Create an OverlayAccount of contract account when the account doesn't
    /// exist before.
    pub fn new_contract_with_admin(
        address: &AddressWithSpace, balance: U256, admin: &Address,
        invalidated_storage: bool, storage_layout: Option<StorageLayout>,
        cip107: bool,
    ) -> Self
    {
        let sponsor_info = if cip107 && address.space == Space::Native {
            SponsorInfo {
                storage_points: Some(Default::default()),
                ..Default::default()
            }
        } else {
            Default::default()
        };
        OverlayAccount {
            address: address.clone(),
            balance,
            nonce: U256::one(),
            admin: admin.clone(),
            sponsor_info,
            storage_value_read_cache: Default::default(),
            storage_value_write_cache: Default::default(),
            storage_owner_lv2_write_cache: Default::default(),
            storage_owner_lv1_write_cache: Default::default(),
            storage_layout_change: storage_layout,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: None,
            vote_stake_list: None,
            code_hash: KECCAK_EMPTY,
            code: None,
            is_newly_created_contract: true,
            invalidated_storage,
        }
    }

    pub fn as_account(&self) -> Account {
        let mut account = Account::new_empty(self.address());

        account.balance = self.balance;
        account.nonce = self.nonce;
        account.code_hash = self.code_hash;
        account.staking_balance = self.staking_balance;
        account.collateral_for_storage = self.collateral_for_storage;
        account.accumulated_interest_return = self.accumulated_interest_return;
        account.admin = self.admin;
        account.sponsor_info = self.sponsor_info.clone();
        account.set_address(self.address);
        account
    }

    pub fn is_contract(&self) -> bool {
        self.code_hash != KECCAK_EMPTY || self.is_newly_created_contract
    }

    fn fresh_storage(&self) -> bool {
        let builtin_address = self.address.space == Space::Native
            && self.address.address.is_builtin_address();
        (self.is_newly_created_contract && !builtin_address)
            || self.invalidated_storage
    }

    pub fn removed_without_update(&self) -> bool {
        self.invalidated_storage && self.as_account().is_default()
    }

    pub fn invalidated_storage(&self) -> bool { self.invalidated_storage }

    pub fn address(&self) -> &AddressWithSpace { &self.address }

    pub fn balance(&self) -> &U256 { &self.balance }

    pub fn sponsor_info(&self) -> &SponsorInfo { &self.sponsor_info }

    pub fn set_sponsor_for_gas(
        &mut self, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    )
    {
        self.address.assert_native();
        self.sponsor_info.sponsor_for_gas = *sponsor;
        self.sponsor_info.sponsor_balance_for_gas = *sponsor_balance;
        self.sponsor_info.sponsor_gas_bound = *upper_bound;
    }

    pub fn set_sponsor_for_collateral(
        &mut self, sponsor: &Address, sponsor_balance: &U256, prop: U256,
    ) -> U256 {
        self.address.assert_native();
        self.sponsor_info.sponsor_for_collateral = *sponsor;
        let inc = sponsor_balance
            .saturating_sub(self.sponsor_info.sponsor_balance_for_collateral);
        self.sponsor_info.sponsor_balance_for_collateral = *sponsor_balance;

        if self.sponsor_info.storage_points.is_some() && !inc.is_zero() {
            let converted_storage_point =
                inc * prop / (U256::from(ONE_CFX_IN_DRIP) + prop);
            self.sponsor_info.sponsor_balance_for_collateral -=
                converted_storage_point;
            self.sponsor_info.storage_points.as_mut().unwrap().unused +=
                converted_storage_point;
            converted_storage_point
        } else {
            U256::zero()
        }
    }

    pub fn admin(&self) -> &Address {
        self.address.assert_native();
        &self.admin
    }

    pub fn sub_sponsor_balance_for_gas(&mut self, by: &U256) {
        self.address.assert_native();
        assert!(self.sponsor_info.sponsor_balance_for_gas >= *by);
        self.sponsor_info.sponsor_balance_for_gas -= *by;
    }

    pub fn add_sponsor_balance_for_gas(&mut self, by: &U256) {
        self.address.assert_native();
        self.sponsor_info.sponsor_balance_for_gas += *by;
    }

    pub fn sub_sponsor_balance_for_collateral(&mut self, by: &U256) {
        self.address.assert_native();
        assert!(self.sponsor_info.sponsor_balance_for_collateral >= *by);
        self.sponsor_info.sponsor_balance_for_collateral -= *by;
    }

    pub fn add_sponsor_balance_for_collateral(&mut self, by: &U256) {
        self.address.assert_native();
        self.sponsor_info.sponsor_balance_for_collateral += *by;
    }

    pub fn set_admin(&mut self, admin: &Address) {
        self.address.assert_native();
        self.admin = admin.clone();
    }

    pub fn check_commission_privilege(
        &self, db: &StateDbGeneric, contract_address: &Address, user: &Address,
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

    pub fn is_cip_107_initialized(&self) -> bool {
        self.sponsor_info.storage_points.is_some()
    }

    /// When CIP 107 is activated, half of the storage will coverte
    pub fn initialize_cip107(&mut self, prop: U256) -> (U256, U256, U256) {
        assert!(self.is_contract());
        let total_collateral = self.sponsor_info.sponsor_balance_for_collateral
            + self.collateral_for_storage;
        let changed_storage_points =
            total_collateral * prop / (U256::from(ONE_CFX_IN_DRIP) + prop);
        let mut storage_points = StoragePoints {
            unused: changed_storage_points,
            used: U256::zero(),
        };

        let burnt_balance_from_balance = std::cmp::min(
            self.sponsor_info.sponsor_balance_for_collateral,
            changed_storage_points,
        );
        let burnt_balance_from_collateral =
            changed_storage_points - burnt_balance_from_balance;

        if !burnt_balance_from_balance.is_zero() {
            self.sponsor_info.sponsor_balance_for_collateral -=
                burnt_balance_from_balance;
        }
        if !burnt_balance_from_collateral.is_zero() {
            self.collateral_for_storage -= burnt_balance_from_collateral;
            storage_points.unused -= burnt_balance_from_collateral;
            storage_points.used += burnt_balance_from_collateral;
        }
        self.sponsor_info.storage_points = Some(storage_points);

        return (
            burnt_balance_from_balance,
            burnt_balance_from_collateral,
            changed_storage_points,
        );
    }

    fn charge_for_sponsored_collateral(&mut self, by: U256) -> U256 {
        assert!(self.is_contract());
        let charge_from_balance =
            std::cmp::min(self.sponsor_info.sponsor_balance_for_collateral, by);
        self.sponsor_info.sponsor_balance_for_collateral -= charge_from_balance;
        self.collateral_for_storage += charge_from_balance;

        let charge_from_points = by - charge_from_balance;
        if !charge_from_points.is_zero() {
            let storage_points = self
                .sponsor_info
                .storage_points
                .as_mut()
                .expect("Storage points should be non-zero");
            storage_points.unused -= charge_from_points;
            storage_points.used += charge_from_points;
        }
        charge_from_points
    }

    fn refund_for_sponsored_collateral(&mut self, by: U256) -> U256 {
        assert!(self.is_contract());
        let refund_from_points = std::cmp::min(
            self.sponsor_info
                .storage_points
                .as_ref()
                .map_or(U256::zero(), |x| x.used),
            by,
        );
        if !refund_from_points.is_zero() {
            let storage_points = self
                .sponsor_info
                .storage_points
                .as_mut()
                .expect("Storage points should be non-zero");
            storage_points.unused += refund_from_points;
            storage_points.used -= refund_from_points;
        }

        let refund_from_balance = by - refund_from_points;
        self.sponsor_info.sponsor_balance_for_collateral += refund_from_balance;
        self.collateral_for_storage -= refund_from_balance;

        refund_from_points
    }

    pub fn staking_balance(&self) -> &U256 {
        self.address.assert_native();
        &self.staking_balance
    }

    pub fn collateral_for_storage(&self) -> U256 {
        self.address.assert_native();
        self.collateral_for_storage
            + self
                .sponsor_info
                .storage_points
                .as_ref()
                .map_or(U256::zero(), |x| x.used)
    }

    pub fn token_collateral_for_storage(&self) -> U256 {
        self.address.assert_native();
        self.collateral_for_storage
    }

    #[cfg(test)]
    pub fn accumulated_interest_return(&self) -> &U256 {
        &self.accumulated_interest_return
    }

    pub fn remove_expired_vote_stake_info(&mut self, block_number: u64) {
        self.address.assert_native();
        assert!(self.vote_stake_list.is_some());
        let vote_stake_list = self.vote_stake_list.as_mut().unwrap();
        vote_stake_list.remove_expired_vote_stake_info(block_number)
    }

    pub fn withdrawable_staking_balance(&self, block_number: u64) -> U256 {
        self.address.assert_native();
        assert!(self.vote_stake_list.is_some());
        let vote_stake_list = self.vote_stake_list.as_ref().unwrap();
        return vote_stake_list
            .withdrawable_staking_balance(self.staking_balance, block_number);
    }

    pub fn storage_value_write_cache(&self) -> &HashMap<Vec<u8>, U256> {
        &self.storage_value_write_cache
    }

    #[cfg(test)]
    pub fn storage_owner_lv1_write_cache(
        &self,
    ) -> &HashMap<Vec<u8>, Option<Address>> {
        &self.storage_owner_lv1_write_cache
    }

    #[cfg(test)]
    pub fn is_newly_created_contract(&self) -> bool {
        self.is_newly_created_contract
    }

    pub fn nonce(&self) -> &U256 { &self.nonce }

    pub fn code_hash(&self) -> H256 { self.code_hash.clone() }

    pub fn is_code_loaded(&self) -> bool {
        self.code.is_some() || self.code_hash == KECCAK_EMPTY
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
        deposit_time: u64, cip_97: bool,
    )
    {
        self.address.assert_native();
        assert!(self.deposit_list.is_some());
        self.sub_balance(&amount);
        let not_maintain_deposit_list =
            cip_97 && self.deposit_list.as_ref().unwrap().0.is_empty();
        self.staking_balance += amount;
        if !not_maintain_deposit_list {
            self.deposit_list.as_mut().unwrap().push(DepositInfo {
                amount,
                deposit_time: deposit_time.into(),
                accumulated_interest_rate,
            });
        }
    }

    /// Withdraw some amount of tokens, return the value of interest.
    pub fn withdraw(
        &mut self, amount: U256, accumulated_interest_rate: U256, cip_97: bool,
    ) -> U256 {
        self.address.assert_native();
        assert!(self.deposit_list.is_some());
        let deposit_list = self.deposit_list.as_mut().unwrap();
        let before_staking_balance = self.staking_balance.clone();
        self.staking_balance -= amount;

        if deposit_list.0.is_empty() {
            self.add_balance(&amount);
            return U256::zero();
        }

        let mut rest = if cip_97 {
            before_staking_balance
        } else {
            amount
        };

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
        self.address.assert_native();
        assert!(self.vote_stake_list.is_some());
        assert!(amount <= self.staking_balance);
        let vote_stake_list = self.vote_stake_list.as_mut().unwrap();
        vote_stake_list.vote_lock(amount, unlock_block_number)
    }

    pub fn add_collateral_for_storage(&mut self, by: &U256) -> U256 {
        self.address.assert_native();
        if self.is_contract() {
            self.charge_for_sponsored_collateral(*by)
        } else {
            self.sub_balance(by);
            self.collateral_for_storage += *by;
            U256::zero()
        }
    }

    pub fn sub_collateral_for_storage(&mut self, by: &U256) -> U256 {
        self.address.assert_native();
        assert!(self.collateral_for_storage >= *by);
        if self.is_contract() {
            self.refund_for_sponsored_collateral(*by)
        } else {
            self.add_balance(by);
            self.collateral_for_storage -= *by;
            U256::zero()
        }
    }

    pub fn record_interest_receive(&mut self, interest: &U256) {
        self.address.assert_native();
        self.accumulated_interest_return += *interest;
    }

    pub fn cache_code(&mut self, db: &StateDbGeneric) -> DbResult<bool> {
        trace!(
            "OverlayAccount::cache_code: ic={}; self.code_hash={:?}, self.code_cache={:?}",
               self.is_code_loaded(), self.code_hash, self.code);

        if self.is_code_loaded() {
            return Ok(true);
        }

        self.code = db.get_code(&self.address, &self.code_hash)?;
        match &self.code {
            Some(_) => Ok(true),
            _ => {
                warn!(
                    "Failed to get code {:?} for address {:?}",
                    self.code_hash, self.address
                );
                Ok(false)
            }
        }
    }

    pub fn cache_staking_info(
        &mut self, cache_deposit_list: bool, cache_vote_list: bool,
        db: &StateDbGeneric,
    ) -> DbResult<bool>
    {
        self.address.assert_native();
        if cache_deposit_list && self.deposit_list.is_none() {
            let deposit_list_opt = if self.fresh_storage() {
                None
            } else {
                db.get_deposit_list(&self.address)?
            };
            self.deposit_list = Some(deposit_list_opt.unwrap_or_default());
        }
        if cache_vote_list && self.vote_stake_list.is_none() {
            let vote_list_opt = if self.fresh_storage() {
                None
            } else {
                db.get_vote_list(&self.address)?
            };
            self.vote_stake_list = Some(vote_list_opt.unwrap_or_default());
        }
        Ok(true)
    }

    pub fn clone_basic(&self) -> Self {
        OverlayAccount {
            address: self.address,
            balance: self.balance,
            nonce: self.nonce,
            admin: self.admin,
            sponsor_info: self.sponsor_info.clone(),
            storage_value_read_cache: Default::default(),
            storage_value_write_cache: Default::default(),
            storage_owner_lv2_write_cache: Default::default(),
            storage_owner_lv1_write_cache: Default::default(),
            storage_layout_change: None,
            staking_balance: self.staking_balance,
            collateral_for_storage: self.collateral_for_storage,
            accumulated_interest_return: self.accumulated_interest_return,
            deposit_list: self.deposit_list.clone(),
            vote_stake_list: self.vote_stake_list.clone(),
            code_hash: self.code_hash,
            code: self.code.clone(),
            is_newly_created_contract: self.is_newly_created_contract,
            invalidated_storage: self.invalidated_storage,
        }
    }

    pub fn clone_dirty(&self) -> Self {
        let mut account = self.clone_basic();
        account.storage_value_write_cache =
            self.storage_value_write_cache.clone();
        account.storage_value_read_cache =
            self.storage_value_read_cache.clone();
        account.storage_owner_lv2_write_cache =
            RwLock::new(self.storage_owner_lv2_write_cache.read().clone());
        account.storage_owner_lv1_write_cache =
            self.storage_owner_lv1_write_cache.clone();
        account.storage_layout_change = self.storage_layout_change.clone();
        account
    }

    pub fn set_storage(&mut self, key: Vec<u8>, value: U256, owner: Address) {
        Arc::make_mut(&mut self.storage_value_write_cache)
            .insert(key.clone(), value);
        if self.address.space == Space::Ethereum
            || self.address.address == SYSTEM_STORAGE_ADDRESS
        {
            return;
        }
        let lv1_write_cache =
            Arc::make_mut(&mut self.storage_owner_lv1_write_cache);
        if value.is_zero() {
            lv1_write_cache.insert(key, None);
        } else {
            lv1_write_cache.insert(key, Some(owner));
        }
    }

    #[cfg(test)]
    pub fn storage_layout_change(&self) -> Option<&StorageLayout> {
        self.storage_layout_change.as_ref()
    }

    #[cfg(test)]
    pub fn set_storage_layout(&mut self, layout: StorageLayout) {
        self.storage_layout_change = Some(layout);
    }

    pub fn cached_storage_at(&self, key: &[u8]) -> Option<U256> {
        if let Some(value) = self.storage_value_write_cache.get(key) {
            return Some(value.clone());
        }
        if let Some(value) = self.storage_value_read_cache.read().get(key) {
            return Some(value.clone());
        }
        None
    }

    // If a contract is removed, and then some one transfer balance to it,
    // `storage_at` will return incorrect value. But this case should never
    // happens.
    pub fn storage_at(
        &self, db: &StateDbGeneric, key: &[u8],
    ) -> DbResult<U256> {
        if let Some(value) = self.cached_storage_at(key) {
            return Ok(value);
        }
        if self.fresh_storage() {
            Ok(U256::zero())
        } else {
            Self::get_and_cache_storage(
                &mut self.storage_value_read_cache.write(),
                Arc::make_mut(&mut *self.storage_owner_lv2_write_cache.write()),
                db,
                &self.address,
                key,
                true, /* cache_ownership */
            )
        }
    }

    pub fn storage_opt_at(
        &self, db: &StateDbGeneric, key: &[u8],
    ) -> DbResult<Option<U256>> {
        if let Some(value) = self.cached_storage_at(key) {
            return Ok(Some(value));
        }
        if self.fresh_storage() {
            Ok(None)
        } else {
            Ok(db
                .get::<StorageValue>(
                    StorageKey::new_storage_key(
                        &self.address.address,
                        key.as_ref(),
                    )
                    .with_space(self.address.space),
                )?
                .map(|v| v.value))
        }
    }

    pub fn change_storage_value(
        &mut self, db: &StateDbGeneric, key: &[u8], value: U256,
    ) -> DbResult<()> {
        let current_value = self.storage_at(db, key)?;
        if !current_value.is_zero() {
            // Constraint requirement: if a key appears in value_write_cache, it
            // must be in owner_lv2_write cache. Safety: since
            // current value is non-zero, this key must appears in
            // lv2_write_cache because `storage_at` loaded it.
            Arc::make_mut(&mut self.storage_value_write_cache)
                .insert(key.to_vec(), value);
        } else {
            warn!("Change storage value outside transaction fails: current value is zero, tx {:?}, key {:?}", self.address, key);
        }
        Ok(())
    }

    fn get_and_cache_storage(
        storage_value_read_cache: &mut HashMap<Vec<u8>, U256>,
        storage_owner_lv2_write_cache: &mut HashMap<Vec<u8>, Option<Address>>,
        db: &StateDbGeneric, address: &AddressWithSpace, key: &[u8],
        cache_ownership: bool,
    ) -> DbResult<U256>
    {
        assert!(!storage_owner_lv2_write_cache.contains_key(key));
        let cache_ownership = cache_ownership
            && address.space == Space::Native
            && address.address != SYSTEM_STORAGE_ADDRESS;

        if let Some(value) = db.get::<StorageValue>(
            StorageKey::new_storage_key(&address.address, key.as_ref())
                .with_space(address.space),
        )? {
            storage_value_read_cache.insert(key.to_vec(), value.value);
            if cache_ownership {
                storage_owner_lv2_write_cache.insert(
                    key.to_vec(),
                    Some(match value.owner {
                        Some(owner) => owner,
                        None => address.address,
                    }),
                );
            }
            Ok(value.value)
        } else {
            storage_value_read_cache.insert(key.to_vec(), U256::zero());
            if cache_ownership {
                storage_owner_lv2_write_cache.insert(key.to_vec(), None);
            }
            Ok(U256::zero())
        }
    }

    pub fn init_code(&mut self, code: Bytes, owner: Address) {
        self.code_hash = keccak(&code);
        self.code = Some(CodeInfo {
            code: Arc::new(code),
            owner,
        });
    }

    pub fn overwrite_with(&mut self, other: OverlayAccount) {
        self.balance = other.balance;
        self.nonce = other.nonce;
        self.admin = other.admin;
        self.sponsor_info = other.sponsor_info;
        self.code_hash = other.code_hash;
        self.code = other.code;
        self.storage_value_read_cache = other.storage_value_read_cache;
        self.storage_value_write_cache = other.storage_value_write_cache;
        self.storage_owner_lv2_write_cache =
            other.storage_owner_lv2_write_cache;
        self.storage_owner_lv1_write_cache =
            other.storage_owner_lv1_write_cache;
        self.storage_layout_change = other.storage_layout_change;
        self.staking_balance = other.staking_balance;
        self.collateral_for_storage = other.collateral_for_storage;
        self.accumulated_interest_return = other.accumulated_interest_return;
        self.deposit_list = other.deposit_list;
        self.vote_stake_list = other.vote_stake_list;
        self.is_newly_created_contract = other.is_newly_created_contract;
        self.invalidated_storage = other.invalidated_storage;
    }

    /// Return the owner of `key` before this execution. If it is `None`, it
    /// means the value of the key is zero before this execution. Otherwise, the
    /// value of the key is nonzero.
    pub fn original_ownership_at(
        &self, db: &StateDbGeneric, key: &Vec<u8>,
    ) -> DbResult<Option<Address>> {
        self.address.assert_native();
        if let Some(value) = self.storage_owner_lv2_write_cache.read().get(key)
        {
            return Ok(value.clone());
        }
        if self.fresh_storage() {
            return Ok(None);
        }
        let storage_value_read_cache =
            &mut self.storage_value_read_cache.write();
        let storage_owner_lv2_write_cache =
            &mut *self.storage_owner_lv2_write_cache.write();
        let storage_owner_lv2_write_cache =
            Arc::make_mut(storage_owner_lv2_write_cache);
        Self::get_and_cache_storage(
            storage_value_read_cache,
            storage_owner_lv2_write_cache,
            db,
            &self.address,
            key,
            true, /* cache_ownership */
        )?;
        Ok(storage_owner_lv2_write_cache
            .get(key)
            .expect("key exists")
            .clone())
    }

    /// Return the storage change of each related account.
    /// Each account is associated with a pair of `(usize, usize)`. The first
    /// value means the number of keys occupied by this account in current
    /// execution. The second value means the number of keys released by this
    /// account in current execution.
    pub fn commit_ownership_change(
        &mut self, db: &StateDbGeneric, substate: &mut Substate,
    ) -> DbResult<()> {
        self.address.assert_native();
        if self.invalidated_storage {
            return Ok(());
        }
        if self.address.address == SYSTEM_STORAGE_ADDRESS {
            return Ok(());
        }
        let storage_owner_lv1_write_cache: Vec<_> =
            Arc::make_mut(&mut self.storage_owner_lv1_write_cache)
                .drain()
                .collect();
        for (k, current_owner_opt) in storage_owner_lv1_write_cache {
            // Get the owner of `k` before execution. If it is `None`, it means
            // the value of the key is zero before execution. Otherwise, the
            // value of the key is nonzero.
            let original_ownership_opt = self.original_ownership_at(db, &k)?;
            if original_ownership_opt != current_owner_opt {
                if let Some(original_owner) = original_ownership_opt.as_ref() {
                    // The key has released from previous owner.
                    substate.record_storage_release(
                        original_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                }
                if let Some(current_owner) = current_owner_opt.as_ref() {
                    // The owner has occupied a new key.
                    substate.record_storage_occupy(
                        current_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                }
            }
            // Commit ownership change to `storage_owner_lv2_write_cache`.
            Arc::make_mut(self.storage_owner_lv2_write_cache.get_mut())
                .insert(k, current_owner_opt);
        }
        assert!(self.storage_owner_lv1_write_cache.is_empty());
        Ok(())
    }

    pub fn commit(
        &mut self, state: &mut State, address: &AddressWithSpace,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        // When committing an overlay account, the execution of an epoch has
        // finished. In this case, all the checkpoints except the bottom one
        // must be removed. (Each checkpoint is a mapping from addresses to
        // overlay accounts.)
        assert_eq!(Arc::strong_count(&self.storage_owner_lv1_write_cache), 1);
        assert_eq!(
            Arc::strong_count(&self.storage_owner_lv2_write_cache.read()),
            1
        );
        assert_eq!(Arc::strong_count(&self.storage_value_write_cache), 1);

        if self.invalidated_storage() {
            state.recycle_storage(
                vec![self.address],
                debug_record.as_deref_mut(),
            )?;
        }

        assert!(self.storage_owner_lv1_write_cache.is_empty());

        let storage_owner_lv2_write_cache =
            &**self.storage_owner_lv2_write_cache.read();
        for (k, v) in Arc::make_mut(&mut self.storage_value_write_cache).drain()
        {
            let address_key =
                StorageKey::new_storage_key(&self.address.address, k.as_ref())
                    .with_space(self.address.space);
            match v.is_zero() {
                true => {
                    state.db.delete(address_key, debug_record.as_deref_mut())?
                }
                false => {
                    let owner = if self.address.space == Space::Ethereum
                        || self.address.address == SYSTEM_STORAGE_ADDRESS
                    {
                        None
                    } else {
                        let current_owner = storage_owner_lv2_write_cache
                            .get(&k)
                            .expect("all key must exist")
                            .expect("owner exists");
                        if current_owner == self.address.address {
                            None
                        } else {
                            Some(current_owner)
                        }
                    };

                    state.db.set::<StorageValue>(
                        address_key,
                        &StorageValue { value: v, owner },
                        debug_record.as_deref_mut(),
                    )?
                }
            }
        }

        if let Some(code_info) = self.code.as_ref() {
            let storage_key = StorageKey::new_code_key(
                &self.address.address,
                &self.code_hash,
            )
            .with_space(self.address.space);
            state.db.set::<CodeInfo>(
                storage_key,
                code_info,
                debug_record.as_deref_mut(),
            )?;
        }

        if let Some(deposit_list) = self.deposit_list.as_ref() {
            self.address.assert_native();
            let storage_key =
                StorageKey::new_deposit_list_key(&self.address.address)
                    .with_space(self.address.space);
            state.db.set::<DepositList>(
                storage_key,
                deposit_list,
                debug_record.as_deref_mut(),
            )?;
        }

        if let Some(vote_stake_list) = self.vote_stake_list.as_ref() {
            self.address.assert_native();
            let storage_key =
                StorageKey::new_vote_list_key(&self.address.address)
                    .with_space(self.address.space);
            state.db.set::<VoteStakeList>(
                storage_key,
                vote_stake_list,
                debug_record.as_deref_mut(),
            )?;
        }

        if let Some(layout) = self.storage_layout_change.clone() {
            state.db.set_storage_layout(
                &self.address,
                layout,
                debug_record.as_deref_mut(),
            )?;
        }

        state.db.set::<Account>(
            StorageKey::new_account_key(&address.address)
                .with_space(address.space),
            &self.as_account(),
            debug_record,
        )?;

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
    // FIXME: remove it.
    /// Entry state.
    pub state: AccountState,
}

impl AccountEntry {
    // FIXME: remove it.
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

impl AccountEntryProtectedMethods for OverlayAccount {
    /// This method is intentionally kept private because the field may not have
    /// been loaded from db.
    fn deposit_list(&self) -> Option<&DepositList> {
        self.deposit_list.as_ref()
    }

    /// This method is intentionally kept private because the field may not have
    /// been loaded from db.
    fn vote_stake_list(&self) -> Option<&VoteStakeList> {
        self.vote_stake_list.as_ref()
    }

    /// This method is intentionally kept private because the field may not have
    /// been loaded from db.
    fn code_size(&self) -> Option<usize> {
        self.code.as_ref().map(|c| c.code_size())
    }

    /// This method is intentionally kept private because the field may not have
    /// been loaded from db.
    fn code(&self) -> Option<Arc<Bytes>> {
        self.code.as_ref().map(|c| c.code.clone())
    }

    /// This method is intentionally kept private because the field may not have
    /// been loaded from db.
    fn code_owner(&self) -> Option<Address> {
        self.code.as_ref().map(|c| c.owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::get_state_for_genesis_write;
    use cfx_storage::tests::new_state_manager_for_unit_test;
    use primitives::is_default::IsDefault;
    use std::str::FromStr;

    fn test_account_is_default(account: &mut OverlayAccount) {
        let storage_manager = new_state_manager_for_unit_test();
        let state = get_state_for_genesis_write(&storage_manager);

        assert!(account.as_account().is_default());

        account.cache_staking_info(true, true, &state.db).unwrap();
        assert!(account.vote_stake_list().unwrap().is_default());
        assert!(account.deposit_list().unwrap().is_default());
    }

    #[test]
    fn new_overlay_account_is_default() {
        let normal_addr =
            Address::from_str("1000000000000000000000000000000000000000")
                .unwrap()
                .with_native_space();
        let builtin_addr =
            Address::from_str("0000000000000000000000000000000000000000")
                .unwrap()
                .with_native_space();

        test_account_is_default(&mut OverlayAccount::new_basic(
            &normal_addr,
            U256::zero(),
        ));
        test_account_is_default(&mut OverlayAccount::new_basic(
            &builtin_addr,
            U256::zero(),
        ));
    }
}
