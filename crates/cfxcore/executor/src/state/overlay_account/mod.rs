// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Overlay Account: The access and manipulation object during execution, which
//! includes both database-stored information and in-execution data of an
//! account.

/// Entry object in cache and checkpoint layers, adding additional markers
/// like dirty bits to the `OverlayAccount` structure.
pub mod account_entry;

/// Implements access functions for the basic fields (e.g., balance, nonce) of
/// an `OverlayAccount`.
mod basic;

/// Implements functions of an `OverlayAccount` related to the storage
/// collateral.
mod collateral;

/// Implements functions of an `OverlayAccount` related to committing changes to
/// the database.
mod commit;

/// Implements functions of an `OverlayAccount` related to loading and accessing
/// logic for lazily loaded fields of an `OverlayAccount` object.
mod ext_fields;

/// Implements functions for constructing `OverlayAccount` objects, frequently
/// utilized in checkpoint logic to create and manage account instances.
mod factory;

/// Implements functions of an `OverlayAccount` related to the sponsor
/// mechanism.
mod sponsor;

/// Implements functions of an `OverlayAccount` related to the staking.
mod staking;

/// Each `OverlayAccount` maintains a 256-bit addressable storage space, managed
/// directly by `OverlayAccount` rather than the state object. This module
/// implements functions of an `OverlayAccount` related to the storage entry
/// manipulation.
mod storage;

mod checkpoints;

mod state_override;

#[cfg(test)]
mod tests;

pub use account_entry::AccountEntry;
pub use ext_fields::RequireFields;

use crate::substate::Substate;
use cfx_types::{
    address_util::AddressUtil, Address, AddressWithSpace, Space, H256, U256,
};
use keccak_hash::KECCAK_EMPTY;
use parking_lot::RwLock;
use primitives::{
    is_default::IsDefault, CodeInfo, DepositList, SponsorInfo, StorageLayout,
    StorageValue, VoteStakeList,
};
use std::{collections::HashMap, sync::Arc};

#[cfg(test)]
use cfx_types::AddressSpaceUtil;

use self::checkpoints::WriteCheckpointLayer;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
/// The access and manipulation object during execution, which includes both
/// database-stored information and in-execution data of an account. It is a
/// basic unit of state caching map and the checkpoint layers (more
/// specifically, its extented struct `AccountEntry`).
///
/// In Conflux consensus executor, after the execution of one epoch, the
/// `OverlayAccount` in cache will be commit to the database.
pub struct OverlayAccount {
    /* ----------------------------------------
    - Database-stored fields for all accounts -
    ---------------------------------------- */
    /// Address of the account
    address: AddressWithSpace,
    /// Balance (in Drip) of the account
    balance: U256,
    /// Nonce of the account,
    nonce: U256,
    /// Code hash of the account.
    code_hash: H256,
    /// Staking balance (in Drip) of the account
    staking_balance: U256,
    /// Collateral (in Drip) of the account
    collateral_for_storage: U256,
    /// Accumulated interest return (in Drip) of the account.
    ///
    /// Inactive after CIP-43.
    accumulated_interest_return: U256,

    /* ---------------------------------------------------
    -  Database-stored fields for contract accounts only -
    --------------------------------------------------- */
    /// Administrator of the account (Only applicable for contract)
    admin: Address,
    /// Sponsor information of the account (Only applicable for contract)
    sponsor_info: SponsorInfo,

    /* ----------------------------------------------------------------
    -  Lazily loaded database-stored fields, also called `ext_fields` -
    ---------------------------------------------------------------- */
    /// List of the deposit info of the account, sorted in increasing order of
    /// `deposit_time`. (`None` indicates not loaded from db.)
    ///
    /// Cleared after CIP-97.
    deposit_list: Option<DepositList>,
    /// List of the vote info of the account. (`None` indicates not loaded from
    /// db.)
    ///
    /// The `unlock_block_number` sorted in increasing order and the `amount`
    /// is sorted in decreasing order. All the `unlock_block_number` and
    /// `amount` is unique in the list.
    vote_stake_list: Option<VoteStakeList>,
    /// The code of the account.  (`None` indicates not loaded from db if
    /// `code_hash` isn't `KECCAK_EMPTY`.)
    code: Option<CodeInfo>,

    /* -------------------
    -  In-execution data -
    ------------------- */
    /// Storage layout change of the account
    storage_layout_change: Option<StorageLayout>,

    /// Read cache for the storage entries of this account for recording
    /// unchanged values.
    storage_read_cache: Arc<RwLock<HashMap<Vec<u8>, StorageValue>>>,

    /// Write cache for the storage entries of this account for recording
    /// changed values.
    storage_write_cache: Arc<RwLock<HashMap<Vec<u8>, StorageValue>>>,
    storage_write_checkpoint:
        Option<WriteCheckpointLayer<Vec<u8>, StorageValue>>,

    /// Transient storage from CIP-142
    transient_storage_cache: Arc<RwLock<HashMap<Vec<u8>, U256>>>,
    transient_storage_checkpoint: Option<WriteCheckpointLayer<Vec<u8>, U256>>,

    /* ---------------
    -  Special flags -
    --------------- */
    /// Indicates whether it is a newly created contract since last commit.
    is_newly_created_contract: bool,

    /// Indicates whether all the storage entries and lazily loaded fields of
    /// this account on the database should be regarded as deleted be and
    /// cleared later. It will be set when such a contract has been killed
    /// since last commit.
    pending_db_clear: bool,

    /// Indicates whether the storage cache entries of this account have been
    /// overrided by the passed-in storage entries.
    /// When this flag is set, the storage entries will only be read from the
    /// cache
    storage_overrided: bool,
}

impl OverlayAccount {
    /// Inditcates if this account can execute bytecode
    pub fn is_contract(&self) -> bool {
        self.code_hash != KECCAK_EMPTY || self.is_newly_created_contract
    }

    /// Inditcates if this account has been killed and has not been re-created
    /// (e.g. sending balance to killed address can recreate it) since last
    /// commit.
    pub fn removed_without_update(&self) -> bool {
        self.pending_db_clear && self.as_account().is_default()
    }

    /// Inditcates if this account's storage entries and lazily loaded fields on
    /// db should be cleared. Upon committing the overlay account, if this flag
    /// is set, db clearing for this account will be triggerred.
    pub fn pending_db_clear(&self) -> bool { self.pending_db_clear }

    /// Inditcates if this account's storage entries and lazily loaded fields on
    /// db are marked invalid (so an entry is empty if not in cache).
    pub fn fresh_storage(&self) -> bool {
        let builtin_address = self.address.space == Space::Native
            && self.address.address.is_builtin_address();
        (self.is_newly_created_contract && !builtin_address)
            || self.pending_db_clear
            || self.storage_overrided
    }
}

impl OverlayAccount {
    #[cfg(test)]
    pub fn is_newly_created_contract(&self) -> bool {
        self.is_newly_created_contract
    }

    #[cfg(test)]
    pub fn is_basic(&self) -> bool { self.code_hash == KECCAK_EMPTY }
}

#[cfg(test)]
mod tests_another {
    use super::*;
    use crate::state::get_state_for_genesis_write;
    use primitives::is_default::IsDefault;
    use std::str::FromStr;

    fn test_account_is_default(account: &mut OverlayAccount) {
        let state = get_state_for_genesis_write();

        assert!(account.as_account().is_default());

        account.cache_ext_fields(true, true, &state.db).unwrap();
        assert!(account.vote_stake_list().is_default());
        assert!(account.deposit_list().is_default());
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
