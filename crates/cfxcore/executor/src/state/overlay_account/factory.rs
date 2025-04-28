use std::sync::Arc;

use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, Space, U256};
use keccak_hash::KECCAK_EMPTY;
use parking_lot::lock_api::RwLock;
use primitives::{Account, SponsorInfo, StorageLayout};

use super::{checkpoints::WriteCheckpointLayer, OverlayAccount};

impl Default for OverlayAccount {
    fn default() -> Self {
        OverlayAccount {
            address: Address::zero().with_native_space(),
            balance: U256::zero(),
            nonce: U256::zero(),
            admin: Address::zero(),
            sponsor_info: Default::default(),
            storage_read_cache: Default::default(),
            storage_committed_cache: Default::default(),
            storage_write_cache: Default::default(),
            storage_write_checkpoint: Default::default(),
            transient_storage_cache: Default::default(),
            transient_storage_checkpoint: Default::default(),
            storage_layout_change: None,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: None,
            vote_stake_list: None,
            code_hash: KECCAK_EMPTY,
            code: None,
            is_newly_created_contract: false,
            pending_db_clear: false,
            storage_overrided: false,
            create_transaction_hash: None,
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
            pending_db_clear: true,
            ..Default::default()
        }
    }

    /// Create an OverlayAccount of contract account when the account doesn't
    /// exist before.
    pub fn new_contract_with_admin(
        address: &AddressWithSpace, balance: U256, admin: &Address,
        pending_db_clear: bool, storage_layout: Option<StorageLayout>,
        cip107: bool,
    ) -> Self {
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
            pending_db_clear,
            ..Default::default()
        }
    }

    /// Create an OverlayAccount of contract account when the account doesn't
    /// exist before.
    #[cfg(test)]
    pub fn new_contract(
        address: &AddressWithSpace, balance: U256, pending_db_clear: bool,
        storage_layout: Option<StorageLayout>,
    ) -> Self {
        Self::new_contract_with_admin(
            &address,
            balance,
            &Address::zero(),
            pending_db_clear,
            storage_layout,
            false,
        )
    }

    /// This function replicates the behavior of the auto-derived `Clone`
    /// implementation, but is manually implemented to explicitly invoke the
    /// `clone` method.
    ///
    /// This approach is necessary because a casual clone could lead to
    /// unintended panic: The `OverlayAccount`s in different checkpoint
    /// layers for the same address shares an `Arc` pointer to the same storage
    /// cache object. During commit, it's asserted that each storage cache
    /// object has only one pointer, meaning each address can only have one
    /// copy.
    ///
    /// Thus, this manual implementation ensures that the cloning of an account
    /// is traceable and controlled。
    pub fn clone_account_for_checkpoint(&self, checkpoint_id: usize) -> Self {
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
            pending_db_clear: self.pending_db_clear,
            storage_write_cache: self.storage_write_cache.clone(),
            storage_write_checkpoint: Some(RwLock::new(
                WriteCheckpointLayer::new_empty(checkpoint_id),
            )),
            storage_committed_cache: self.storage_committed_cache.clone(),
            storage_read_cache: self.storage_read_cache.clone(),
            transient_storage_cache: self.transient_storage_cache.clone(),
            transient_storage_checkpoint: Some(
                WriteCheckpointLayer::new_empty(checkpoint_id),
            ),
            storage_layout_change: self.storage_layout_change.clone(),
            storage_overrided: self.storage_overrided,
            create_transaction_hash: self.create_transaction_hash.clone(),
        }
    }

    pub fn clone_from_committed_cache(&self) -> Self {
        assert!(self.storage_write_checkpoint.is_none());
        assert!(self.transient_storage_checkpoint.is_none());
        assert!(self.storage_write_cache.read().is_empty());
        assert_eq!(Arc::strong_count(&self.storage_read_cache), 1);
        assert_eq!(Arc::strong_count(&self.storage_committed_cache), 1);
        assert_eq!(Arc::strong_count(&self.storage_write_cache), 1);
        assert_eq!(Arc::strong_count(&self.transient_storage_cache), 1);

        // This is a mistake from the early implementation of transient storage,
        // in which the transient_storage_cache is not cleared.
        let transient_storage_cache =
            Arc::new(RwLock::new(self.transient_storage_cache.read().clone()));

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
            pending_db_clear: self.pending_db_clear,
            storage_write_cache: Default::default(),
            storage_write_checkpoint: None,
            storage_committed_cache: self.storage_committed_cache.clone(),
            storage_read_cache: self.storage_read_cache.clone(),
            transient_storage_cache,
            transient_storage_checkpoint: None,
            storage_layout_change: self.storage_layout_change.clone(),
            storage_overrided: self.storage_overrided,
            create_transaction_hash: self.create_transaction_hash.clone(),
        }
    }

    pub fn clone_account(&self) -> Self {
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
            pending_db_clear: self.pending_db_clear,
            storage_write_cache: Arc::new(RwLock::new(
                self.storage_write_cache.read().clone(),
            )),
            storage_write_checkpoint: None,
            storage_read_cache: Arc::new(RwLock::new(
                self.storage_read_cache.read().clone(),
            )),
            transient_storage_cache: Arc::new(RwLock::new(
                self.transient_storage_cache.read().clone(),
            )),
            storage_committed_cache: Arc::new(RwLock::new(
                self.storage_committed_cache.read().clone(),
            )),
            transient_storage_checkpoint: None,
            storage_layout_change: self.storage_layout_change.clone(),
            storage_overrided: self.storage_overrided,
            create_transaction_hash: self.create_transaction_hash.clone(),
        }
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
}
