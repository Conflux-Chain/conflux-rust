use crate::try_loaded;
use cfx_statedb::Result as DbResult;
use cfx_types::{AddressSpaceUtil, AddressWithSpace, Space, H256};
use cfx_vm_types::ActionParams;
use primitives::AccessListItem;

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
        self.cache.read().contains_key(address)
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

    pub fn set_tx_access_list(
        &mut self, space: Space, access_list: &[AccessListItem],
    ) {
        let access_list = access_list
            .iter()
            .map(|x| {
                (
                    x.address.with_space(space),
                    x.storage_keys.iter().cloned().collect(),
                )
            })
            .collect();

        self.tx_access_list = Some(access_list);
    }

    pub fn touch_tx_addresses(&self, params: &ActionParams) -> DbResult<()> {
        self.touch(&params.address.with_space(params.space))?;
        self.touch(&params.sender.with_space(params.space))?;
        Ok(())
    }

    pub fn clear_tx_access_list(&mut self) { self.tx_access_list = None; }
}
