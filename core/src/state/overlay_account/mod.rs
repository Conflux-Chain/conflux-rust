// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[cfg(test)]
mod tests;

mod basic;
mod collateral;
mod commit;
mod factory;
mod sponsor;
mod staking;
mod storage;

use super::{
    account_entry::AccountEntry, substate::Substate,
    AccountEntryProtectedMethods,
};

use crate::{bytes::Bytes, hash::KECCAK_EMPTY};

use cfx_statedb::{Result as DbResult, StateDbExt, StateDbGeneric};
#[cfg(test)]
use cfx_types::AddressSpaceUtil;
use cfx_types::{
    address_util::AddressUtil, Address, AddressWithSpace, Space, H256, U256,
};
use parking_lot::RwLock;
use primitives::{
    is_default::IsDefault, CodeInfo, DepositList, SponsorInfo, StorageLayout,
    VoteStakeList,
};
use std::{collections::HashMap, sync::Arc};

pub use sponsor::COMMISSION_PRIVILEGE_SPECIAL_KEY;

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
    pub fn is_contract(&self) -> bool {
        self.code_hash != KECCAK_EMPTY || self.is_newly_created_contract
    }

    pub fn removed_without_update(&self) -> bool {
        self.invalidated_storage && self.as_account().is_default()
    }

    #[cfg(test)]
    pub fn is_newly_created_contract(&self) -> bool {
        self.is_newly_created_contract
    }

    #[cfg(test)]
    pub fn is_basic(&self) -> bool { self.code_hash == KECCAK_EMPTY }

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

    fn fresh_storage(&self) -> bool {
        let builtin_address = self.address.space == Space::Native
            && self.address.address.is_builtin_address();
        (self.is_newly_created_contract && !builtin_address)
            || self.invalidated_storage
    }

    pub fn invalidated_storage(&self) -> bool { self.invalidated_storage }

    pub fn cache_ext_fields(
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
mod tests_another {
    use super::*;
    use crate::test_helpers::get_state_for_genesis_write;
    use cfx_storage::tests::new_state_manager_for_unit_test;
    use primitives::is_default::IsDefault;
    use std::str::FromStr;

    fn test_account_is_default(account: &mut OverlayAccount) {
        let storage_manager = new_state_manager_for_unit_test();
        let state = get_state_for_genesis_write(&storage_manager);

        assert!(account.as_account().is_default());

        account.cache_ext_fields(true, true, &state.db).unwrap();
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
