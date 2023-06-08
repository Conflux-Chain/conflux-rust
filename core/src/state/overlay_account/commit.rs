use super::{AccountEntryProtectedMethods};

use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::{
    internal_contract_addresses::SYSTEM_STORAGE_ADDRESS,
};
use cfx_statedb::{Result as DbResult, StateDb, StateDbExt};
#[cfg(test)]
use cfx_types::AddressSpaceUtil;
use cfx_types::{
    AddressWithSpace, Space,
};

use primitives::{
    Account, CodeInfo, DepositList, StorageKey,
    StorageValue, VoteStakeList,
};
use std::{sync::Arc};

use super::OverlayAccount;

impl OverlayAccount {
    pub fn commit(
        &mut self, db: &mut StateDb, address: &AddressWithSpace,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        // When committing an overlay account, the execution of an epoch has
        // finished. In this case, all the checkpoints except the bottom one
        // must be removed. (Each checkpoint is a mapping from addresses to
        // overlay accounts.)
        assert_eq!(Arc::strong_count(&self.storage_owner_lv1_write_cache), 1);
        assert_eq!(
            Arc::strong_count(&self.storage_owner_lv2_write_cache.read()),
            1
        );
        assert_eq!(Arc::strong_count(&self.storage_value_write_cache), 1);

        assert!(self.storage_owner_lv1_write_cache.is_empty());

        let storage_owner_lv2_write_cache =
            &**self.storage_owner_lv2_write_cache.read();
        for (k, v) in Arc::make_mut(&mut self.storage_value_write_cache).drain()
        {
            let address_key =
                StorageKey::new_storage_key(&self.address.address, k.as_ref())
                    .with_space(self.address.space);
            match v.is_zero() {
                true => db.delete(address_key, debug_record.as_deref_mut())?,
                false => {
                    let owner = if self.address.space == Space::Ethereum
                        || self.address.address == SYSTEM_STORAGE_ADDRESS
                    {
                        None
                    } else {
                        let current_owner = storage_owner_lv2_write_cache
                            .get(&k)
                            .expect("all key must exist")
                            .expect("owner exists");
                        if current_owner == self.address.address {
                            None
                        } else {
                            Some(current_owner)
                        }
                    };

                    db.set::<StorageValue>(
                        address_key,
                        &StorageValue { value: v, owner },
                        debug_record.as_deref_mut(),
                    )?
                }
            }
        }

        if let Some(code_info) = self.code.as_ref() {
            let storage_key = StorageKey::new_code_key(
                &self.address.address,
                &self.code_hash,
            )
            .with_space(self.address.space);
            db.set::<CodeInfo>(
                storage_key,
                code_info,
                debug_record.as_deref_mut(),
            )?;
        }

        if let Some(deposit_list) = self.deposit_list.as_ref() {
            self.address.assert_native();
            let storage_key =
                StorageKey::new_deposit_list_key(&self.address.address)
                    .with_space(self.address.space);
            db.set::<DepositList>(
                storage_key,
                deposit_list,
                debug_record.as_deref_mut(),
            )?;
        }

        if let Some(vote_stake_list) = self.vote_stake_list.as_ref() {
            self.address.assert_native();
            let storage_key =
                StorageKey::new_vote_list_key(&self.address.address)
                    .with_space(self.address.space);
            db.set::<VoteStakeList>(
                storage_key,
                vote_stake_list,
                debug_record.as_deref_mut(),
            )?;
        }

        if let Some(layout) = self.storage_layout_change.clone() {
            db.set_storage_layout(
                &self.address,
                layout,
                debug_record.as_deref_mut(),
            )?;
        }

        db.set::<Account>(
            StorageKey::new_account_key(&address.address)
                .with_space(address.space),
            &self.as_account(),
            debug_record,
        )?;

        Ok(())
    }
}
