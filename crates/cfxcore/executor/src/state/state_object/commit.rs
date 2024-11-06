use super::State;
use cfx_internal_common::{
    debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
};
use cfx_statedb::{access_mode, Result as DbResult};
use cfx_types::AddressWithSpace;
use primitives::{Account, EpochId, StorageKey};

pub struct StateCommitResult {
    pub state_root: StateRootWithAuxInfo,
    pub accounts_for_txpool: Vec<Account>,
}

impl State {
    /// Commit everything to the storage.
    pub fn commit(
        mut self, epoch_id: EpochId,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateCommitResult> {
        debug!("Commit epoch[{}]", epoch_id);

        let accounts_for_txpool =
            self.apply_changes_to_statedb(debug_record.as_deref_mut())?;
        let state_root = self.db.commit(epoch_id, debug_record)?;
        Ok(StateCommitResult {
            state_root,
            accounts_for_txpool,
        })
    }

    /// Commit to the statedb and compute state root. Only called in the genesis
    pub fn compute_state_root_for_genesis(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<StateRootWithAuxInfo> {
        self.apply_changes_to_statedb(debug_record.as_deref_mut())?;
        self.db.compute_state_root(debug_record)
    }

    /// Apply changes for the accounts and global variables to the statedb.
    fn apply_changes_to_statedb(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<Vec<Account>> {
        debug!("state.commit_changes");

        let accounts_for_txpool =
            self.commit_dirty_accounts(debug_record.as_deref_mut())?;
        self.global_stat.commit(&mut self.db, debug_record)?;
        Ok(accounts_for_txpool)
    }

    fn commit_dirty_accounts(
        &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<Vec<Account>> {
        assert!(self.no_checkpoint());

        let cache_items = self.cache.get_mut().drain();
        let mut to_commit_accounts = cache_items
            .filter_map(|(_, acc)| acc.into_to_commit_account())
            .collect::<Vec<_>>();
        to_commit_accounts.sort_by(|a, b| a.address().cmp(b.address()));

        let mut accounts_to_notify = vec![];

        for account in to_commit_accounts.into_iter() {
            let address = *account.address();

            if account.pending_db_clear() {
                self.recycle_storage(
                    vec![address],
                    debug_record.as_deref_mut(),
                )?;
            }

            if !account.removed_without_update() {
                accounts_to_notify.push(account.as_account());
                account.commit(
                    &mut self.db,
                    &address,
                    debug_record.as_deref_mut(),
                )?;
            }
        }
        Ok(accounts_to_notify)
    }

    fn recycle_storage(
        &mut self, killed_addresses: Vec<AddressWithSpace>,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()> {
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

impl State {
    // Some test code will reuse state incorrectly, so we implement a version
    // which does not take ownership when committing.
    #[cfg(test)]
    pub fn commit_for_test(&mut self, epoch_id: EpochId) -> DbResult<()> {
        self.apply_changes_to_statedb(None)?;
        self.db.commit(epoch_id, None)?;
        Ok(())
    }
}
