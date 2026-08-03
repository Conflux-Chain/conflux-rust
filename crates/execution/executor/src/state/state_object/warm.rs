use crate::try_loaded;
use cfx_statedb::Result as DbResult;
use cfx_types::{AddressSpaceUtil, AddressWithSpace, Space, H256};
use cfx_vm_types::ActionParams;
use primitives::AccessListItem;
use std::collections::{HashMap, HashSet};

use super::State;

impl State {
    pub fn is_warm_account(&self, address: &AddressWithSpace) -> bool {
        if self
            .tx_access_list
            .as_ref()
            .map_or(false, |x| x.contains_key(address))
        {
            return true;
        }
        self.cache.read().get(address).map_or(false, |x| x.warm)
    }

    pub fn is_warm_storage_entry(
        &self, address: &AddressWithSpace, key: &H256,
    ) -> DbResult<bool> {
        if self.is_warm_storage_entry_in_access_list(address, key) {
            return Ok(true);
        }

        let acc = try_loaded!(self.read_account_lock(address));
        Ok(acc.is_warm_storage_entry(&key[..]))
    }

    fn is_warm_storage_entry_in_access_list(
        &self, address: &AddressWithSpace, key: &H256,
    ) -> bool {
        let Some(access_list) = self.tx_access_list.as_ref() else {
            return false;
        };
        let Some(account) = access_list.get(address) else {
            return false;
        };
        account.contains(key)
    }

    /// Pre-warms the addresses and storage keys carried by the transaction's
    /// access list.
    ///
    /// EIP-2930 permits the same address to appear in more than one entry, in
    /// which case the warmed storage keys are the union over all of its
    /// entries. Before CIP-176 a later entry replaced the storage keys
    /// recorded by an earlier one, leaving the earlier keys cold even though
    /// the transaction was charged for them.
    pub fn set_tx_access_list(
        &mut self, space: Space, access_list: &[AccessListItem], cip176: bool,
    ) {
        let access_list = if cip176 {
            let mut warmed: HashMap<AddressWithSpace, HashSet<H256>> =
                HashMap::new();
            for x in access_list {
                warmed
                    .entry(x.address.with_space(space))
                    .or_default()
                    .extend(x.storage_keys.iter().cloned());
            }
            warmed
        } else {
            access_list
                .iter()
                .map(|x| {
                    (
                        x.address.with_space(space),
                        x.storage_keys.iter().cloned().collect(),
                    )
                })
                .collect()
        };

        self.tx_access_list = Some(access_list);
    }

    pub fn touch_tx_addresses(&self, params: &ActionParams) -> DbResult<()> {
        self.touch(&params.address.with_space(params.space))?;
        self.touch(&params.sender.with_space(params.space))?;
        Ok(())
    }

    pub fn clear_tx_access_list(&mut self) { self.tx_access_list = None; }

    pub fn update_state_post_tx_execution(
        &mut self, retain_transient_storage: bool,
    ) {
        self.clear_tx_access_list();
        self.commit_cache(retain_transient_storage);
    }
}
