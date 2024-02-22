use super::OverlayAccount;
use cfx_bytes::Bytes;
use cfx_statedb::{
    ErrorKind as DbErrorKind, Result as DbResult, StateDbExt, StateDbGeneric,
};
use cfx_types::Address;
use keccak_hash::KECCAK_EMPTY;
use primitives::{DepositList, VoteStakeList};
use std::sync::Arc;

impl OverlayAccount {
    /// Check should load lazily maintained fields
    pub fn should_load_ext_fields(&self, require: RequireFields) -> bool {
        trace!("update_account_cache account={:?}", self);
        match require {
            RequireFields::None => false,
            RequireFields::Code => !self.is_code_loaded(),
            RequireFields::DepositList => self.deposit_list.is_none(),
            RequireFields::VoteStakeList => self.vote_stake_list.is_none(),
        }
    }

    /// Load lazily maintained code
    pub fn cache_code(&mut self, db: &StateDbGeneric) -> DbResult<()> {
        trace!(
            "OverlayAccount::cache_code: ic={}; self.code_hash={:?}, self.code_cache={:?}",
               self.is_code_loaded(), self.code_hash, self.code);

        if self.is_code_loaded() {
            return Ok(());
        }

        self.code = db.get_code(&self.address, &self.code_hash)?;
        if self.code.is_none() {
            warn!(
                "Failed to get code {:?} for address {:?}",
                self.code_hash, self.address
            );

            bail!(DbErrorKind::IncompleteDatabase(self.address.address));
        }

        Ok(())
    }

    /// Load lazily maintained deposit list and vote list.
    pub fn cache_ext_fields(
        &mut self, cache_deposit_list: bool, cache_vote_list: bool,
        db: &StateDbGeneric,
    ) -> DbResult<()> {
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
        Ok(())
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum RequireFields {
    None,
    Code,
    DepositList,
    VoteStakeList,
}

const NOT_LOADED_ERR: &'static str =
    "OverlayAccount Ext fields not loaded before read";

impl OverlayAccount {
    /// To prevent panics from reading ext fields without loading from the DB,
    /// these method are restricted to be visible only within the `state`
    /// module.
    pub(in crate::state) fn deposit_list(&self) -> &DepositList {
        self.deposit_list.as_ref().expect(NOT_LOADED_ERR)
    }

    /// To prevent panics from reading ext fields without loading from the DB,
    /// these method are restricted to be visible only within the `state`
    /// module.
    pub(in crate::state) fn vote_stake_list(&self) -> &VoteStakeList {
        self.vote_stake_list.as_ref().expect(NOT_LOADED_ERR)
    }

    /// To prevent panics from reading ext fields without loading from the DB,
    /// these method are restricted to be visible only within the `state`
    /// module.
    pub(in crate::state) fn code_size(&self) -> usize {
        if self.code_hash == KECCAK_EMPTY {
            0
        } else {
            self.code.as_ref().expect(NOT_LOADED_ERR).code_size()
        }
    }

    /// To prevent panics from reading ext fields without loading from the DB,
    /// these method are restricted to be visible only within the `state`
    /// module.
    pub(in crate::state) fn code(&self) -> Option<Arc<Bytes>> {
        if self.code_hash == KECCAK_EMPTY {
            None
        } else {
            Some(self.code.as_ref().expect(NOT_LOADED_ERR).code.clone())
        }
    }

    /// To prevent panics from reading ext fields without loading from the DB,
    /// these method are restricted to be visible only within the `state`
    /// module.
    pub(in crate::state) fn code_owner(&self) -> Address {
        if self.code_hash == KECCAK_EMPTY {
            Address::zero()
        } else {
            self.code.as_ref().expect(NOT_LOADED_ERR).owner
        }
    }
}
