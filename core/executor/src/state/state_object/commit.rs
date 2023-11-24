use super::State;
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_statedb::{access_mode, Result as DbResult};
use cfx_types::AddressWithSpace;
use primitives::{Account, EpochId, StorageKey};

impl State {
    // It's guaranteed that the second call of this method is a no-op.
    pub fn compute_state_root(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo> {
        debug!("state.compute_state_root");

        assert!(self.checkpoints.get_mut().is_empty());

        let mut sorted_dirty_accounts =
            self.cache.get_mut().drain().collect::<Vec<_>>();
        sorted_dirty_accounts.sort_by(|a, b| a.0.cmp(&b.0));

        for (address, entry) in sorted_dirty_accounts.into_iter() {
            let account = if let Some(account) = entry.into_account() {
                account
            } else {
                continue;
            };

            if account.invalidated_storage() {
                self.recycle_storage(
                    vec![address],
                    debug_record.as_deref_mut(),
                )?;
            }

            if account.removed_without_update() {
                // TODO: seems useless
                self.accounts_to_notify.push(Err(address));
            } else {
                self.accounts_to_notify.push(Ok(account.as_account()));
                account.commit(
                    &mut self.db,
                    &address,
                    debug_record.as_deref_mut(),
                )?;
            }
        }

        self.global_stat
            .commit(&mut self.db, debug_record.as_deref_mut())?;
        self.db.compute_state_root(debug_record)
    }

    pub fn commit(
        &mut self, epoch_id: EpochId,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo>
    {
        debug!("Commit epoch[{}]", epoch_id);
        self.compute_state_root(debug_record.as_deref_mut())?;
        Ok(self.db.commit(epoch_id, debug_record)?)
    }

    pub fn accounts_for_txpool(&self) -> Vec<Account> {
        self.accounts_to_notify
            .iter()
            .filter_map(|x| match x {
                Ok(account) => Some(account.clone()),
                _ => None,
            })
            .collect()
    }

    /// Assume that only contract with zero `collateral_for_storage` will be
    /// killed.
    fn recycle_storage(
        &mut self, killed_addresses: Vec<AddressWithSpace>,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        // TODO: Think about kill_dust and collateral refund.
        for address in &killed_addresses {
            self.db.delete_all::<access_mode::Write>(
                StorageKey::new_storage_root_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete_all::<access_mode::Write>(
                StorageKey::new_code_root_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_account_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_deposit_list_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
            self.db.delete(
                StorageKey::new_vote_list_key(&address.address)
                    .with_space(address.space),
                debug_record.as_deref_mut(),
            )?;
        }
        Ok(())
    }
}
