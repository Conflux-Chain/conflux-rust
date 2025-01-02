use std::collections::HashMap;

use super::State;
use crate::state::{
    overlay_account::{AccountEntry, OverlayAccount, RequireFields},
    CleanupMode,
};
use cfx_rpc_eth_types::StateOverride;
use cfx_statedb::Result as DbResult;
use cfx_types::{AddressWithSpace, Space, H256, U256};

/// Apply the state override to the state object, only used for rpc call eg
/// eth_call, eth_estimateGas etc.
impl State {
    pub(super) fn apply_override(
        &mut self, state_override: &StateOverride, space: Space,
    ) -> DbResult<()> {
        assert!(self.checkpoints.read().is_empty());

        for (address, account) in state_override.iter() {
            let addr_with_space = AddressWithSpace {
                address: address.to_owned(),
                space,
            };

            self.prefetch(&addr_with_space, RequireFields::Code)?;

            // apply the overrides
            if let Some(balance) = account.balance {
                let mut cleanup_mode = CleanupMode::NoEmpty;
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
                (Some(state), None) => {
                    self.override_state(&addr_with_space, &state, true)?;
                }
                (None, Some(diff)) => {
                    self.override_state(&addr_with_space, &diff, false)?;
                }
                (Some(_state), Some(_diff)) => unreachable!(), /* the rpc layer will check this, so it should not happen here */
                (None, None) => {}
            }

            if account.move_precompile_to.is_some() {
                // TODO: impl move precompile to logic
            }
        }
        Ok(())
    }

    /// Override the storage read cache of an account.
    /// If `complete_override` is true, the cache will be replaced by the given
    /// state. Otherwise, the cache will be updated by the given state.
    fn override_state(
        &mut self, address: &AddressWithSpace, state: &HashMap<H256, H256>,
        complete_override: bool,
    ) -> DbResult<()> {
        let mut cache = self.cache.write();
        match cache.get_mut(address) {
            None | Some(AccountEntry::DbAbsent) => {
                let mut overlay_acc = OverlayAccount::default();
                overlay_acc
                    .override_storage_read_cache(state, complete_override);
                cache.insert(*address, AccountEntry::new_dirty(overlay_acc));
            }
            Some(acc) => {
                let acc = acc.account_mut().unwrap();
                acc.override_storage_read_cache(state, complete_override);
            }
        }

        Ok(())
    }
}
