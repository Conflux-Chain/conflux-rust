use crate::hash::KECCAK_EMPTY;
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, Space, U256};
use parking_lot::RwLock;
use primitives::{Account, SponsorInfo, StorageLayout};

use super::{AccountEntry, OverlayAccount};

impl Default for OverlayAccount {
    fn default() -> Self {
        OverlayAccount {
            address: Address::zero().with_native_space(),
            balance: U256::zero(),
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
            staking_balance: account.staking_balance,
            collateral_for_storage: account.collateral_for_storage,
            accumulated_interest_return: account.accumulated_interest_return,
            code_hash: account.code_hash,
            ..Default::default()
        };

        overlay_account
    }

    /// Create an OverlayAccount of basic account when the account doesn't exist
    /// before.
    pub fn new_basic(address: &AddressWithSpace, balance: U256) -> Self {
        OverlayAccount {
            address: address.clone(),
            balance,
            ..Default::default()
        }
    }

    /// Create an OverlayAccount of basic account when the account doesn't exist
    /// before.
    pub fn new_removed(address: &AddressWithSpace) -> Self {
        OverlayAccount {
            address: address.clone(),
            invalidated_storage: true,
            ..Default::default()
        }
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
            storage_layout_change: storage_layout,
            is_newly_created_contract: true,
            invalidated_storage,
            ..Default::default()
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

    pub fn clone_basic(&self) -> Self {
        OverlayAccount {
            address: self.address,
            balance: self.balance,
            nonce: self.nonce,
            admin: self.admin,
            sponsor_info: self.sponsor_info.clone(),
            staking_balance: self.staking_balance,
            collateral_for_storage: self.collateral_for_storage,
            accumulated_interest_return: self.accumulated_interest_return,
            deposit_list: self.deposit_list.clone(),
            vote_stake_list: self.vote_stake_list.clone(),
            code_hash: self.code_hash,
            code: self.code.clone(),
            is_newly_created_contract: self.is_newly_created_contract,
            invalidated_storage: self.invalidated_storage,
            ..Default::default()
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
}

impl OverlayAccount {
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

    pub fn into_dirty_entry(self) -> AccountEntry {
        AccountEntry::new_dirty(Some(self))
    }
}
