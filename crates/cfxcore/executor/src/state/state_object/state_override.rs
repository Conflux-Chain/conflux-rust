use super::State;
use crate::state::overlay_account::AccountEntry;
use cfx_rpc_eth_types::StateOverride;
use cfx_statedb::{Result as DbResult, StateDbExt};
use cfx_types::{AddressWithSpace, Space};

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

            let loaded_account = self.db.get_account(&addr_with_space)?;
            let account_entry = AccountEntry::from_loaded_and_override(
                &addr_with_space,
                loaded_account,
                account,
            );

            self.cache.write().insert(addr_with_space, account_entry);
        }
        Ok(())
    }
}
