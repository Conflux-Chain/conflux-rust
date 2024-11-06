use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_statedb::{Result as DbResult, StateDb, StateDbExt};
use cfx_types::AddressWithSpace;
use primitives::{
    Account, CodeInfo, DepositList, StorageKey, StorageValue, VoteStakeList,
};

use super::OverlayAccount;

impl OverlayAccount {
    pub fn commit(
        self, db: &mut StateDb, address: &AddressWithSpace,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()> {
        // When committing an overlay account, the execution of an epoch has
        // finished. In this case, all the checkpoints except the bottom one
        // must be removed. (Each checkpoint is a mapping from addresses to
        // overlay accounts.)

        // Commit storage entries

        assert!(self.storage_write_checkpoint.is_none());
        let write_cache = &mut self.storage_write_cache.write();
        for (k, mut v) in write_cache.drain() {
            let address_key =
                StorageKey::new_storage_key(&self.address.address, k.as_ref())
                    .with_space(self.address.space);
            let debug_record = debug_record.as_deref_mut();
            if v.owner == Some(self.address.address) {
                v.owner = None;
            }
            match v.value.is_zero() {
                true => db.delete(address_key, debug_record)?,
                false => {
                    db.set::<StorageValue>(address_key, &v, debug_record)?
                }
            }
        }

        // Commit code

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

        // Commit deposit list

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

        // Commit votestake list

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

        // Commit storage layout

        if let Some(layout) = self.storage_layout_change.clone() {
            db.set_storage_layout(
                &self.address,
                layout,
                debug_record.as_deref_mut(),
            )?;
        }

        // Commit basic fields

        db.set::<Account>(
            StorageKey::new_account_key(&address.address)
                .with_space(address.space),
            &self.as_account(),
            debug_record,
        )?;

        Ok(())
    }
}
