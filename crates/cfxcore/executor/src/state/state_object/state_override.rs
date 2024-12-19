use std::collections::HashMap;

use super::State;
use crate::state::{
    overlay_account::{AccountEntry, OverlayAccount, RequireFields},
    CleanupMode,
};
use cfx_rpc_eth_types::StateOverride;
use cfx_statedb::{Error as DbError, Result as DbResult};
use cfx_types::{AddressWithSpace, Space, H256, U256};

impl State {
    // Apply the state override to the state object, used for rpc call eg
    // eth_call
    pub fn apply_override(
        &mut self, state_override: &StateOverride, space: Space,
    ) -> DbResult<()> {
        for (address, account) in state_override.iter() {
            let addr_with_space = AddressWithSpace {
                address: address.to_owned(),
                space,
            };

            self.prefetch(&addr_with_space, RequireFields::Code)?;

            // apply the overrides
            if let Some(balance) = account.balance {
                let mut cleanup_mode = CleanupMode::NoEmpty; // TODO: check the cleanup mode is used correctly
                let current_balance = self.balance(&addr_with_space)?;
                if current_balance > U256::zero() {
                    self.sub_balance(
                        &addr_with_space,
                        &current_balance,
                        &mut cleanup_mode,
                    )?;
                }
                self.add_balance(&addr_with_space, &balance, cleanup_mode)?;
            }

            if let Some(nonce) = account.nonce {
                self.set_nonce(&addr_with_space, &U256::from(nonce))?;
            }

            if let Some(code) = account.code.clone() {
                self.init_code(&addr_with_space, code, address.to_owned())?;
            }

            match (account.state.clone(), account.state_diff.clone()) {
                (Some(_state), Some(_diff)) => {
                    return Err(DbError::Msg(
                        "Cannot set both state and state_diff".to_string(),
                    ));
                }
                (Some(state), None) => {
                    self.override_state(&addr_with_space, &state)?;
                }
                (None, Some(diff)) => {
                    self.apply_state_diff(&addr_with_space, &diff)?;
                }
                (None, None) => {}
            }

            if account.move_precompile_to.is_some() {
                // TODO: impl move precompile
            }
        }
        Ok(())
    }

    fn override_state(
        &mut self, address: &AddressWithSpace, state: &HashMap<H256, H256>,
    ) -> DbResult<()> {
        let mut cache = self.cache.write();
        let maybe_acc = cache.get_mut(address);
        if maybe_acc.is_none() {
            let mut overlay_acc = OverlayAccount::default();
            overlay_acc.override_storage_read_cache(state);
            cache.insert(*address, AccountEntry::new_dirty(overlay_acc));
        } else {
            let acc = maybe_acc.unwrap();
            if acc.is_db_absent() {
                let mut overlay_acc = OverlayAccount::default();
                overlay_acc.override_storage_read_cache(state);
                *acc = AccountEntry::new_dirty(overlay_acc);
            } else {
                let acc = acc.account_mut().unwrap();
                acc.override_storage_read_cache(state);
            }
        }
        Ok(())
    }

    fn apply_state_diff(
        &mut self, address: &AddressWithSpace, diff: &HashMap<H256, H256>,
    ) -> DbResult<()> {
        let mut cache = self.cache.write();
        let maybe_acc = cache.get_mut(address);
        if maybe_acc.is_none() {
            let mut overlay_acc = OverlayAccount::default();
            overlay_acc.apply_diff_to_storage_read_cache(diff);
            cache.insert(*address, AccountEntry::new_dirty(overlay_acc));
        } else {
            let acc = maybe_acc.unwrap();
            if acc.is_db_absent() {
                let mut overlay_acc = OverlayAccount::default();
                overlay_acc.apply_diff_to_storage_read_cache(diff);
                *acc = AccountEntry::new_dirty(overlay_acc);
            } else {
                let acc = acc.account_mut().unwrap();
                acc.apply_diff_to_storage_read_cache(diff);
            }
        }
        Ok(())
    }
}
