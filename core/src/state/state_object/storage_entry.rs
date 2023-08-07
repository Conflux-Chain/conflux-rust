use super::State;
use cfx_parameters::internal_contract_addresses::SYSTEM_STORAGE_ADDRESS;
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, U256};

// System Storages
impl State {
    pub fn get_system_storage(&self, key: &[u8]) -> DbResult<U256> {
        self.storage_at(&SYSTEM_STORAGE_ADDRESS.with_native_space(), key)
    }

    pub fn set_system_storage(
        &mut self, key: Vec<u8>, value: U256,
    ) -> DbResult<()> {
        self.set_storage(
            &SYSTEM_STORAGE_ADDRESS.with_native_space(),
            key,
            value,
            // The system storage data have no owner, and this parameter is
            // ignored.
            Default::default(),
        )
    }

    pub fn storage_at(
        &self, address: &AddressWithSpace, key: &[u8],
    ) -> DbResult<U256> {
        let acc = try_loaded!(self.read_account_lock(address));
        acc.storage_at(&self.db, key)
    }

    pub fn set_storage(
        &mut self, address: &AddressWithSpace, key: Vec<u8>, value: U256,
        owner: Address,
    ) -> DbResult<()>
    {
        noop_if!(self.storage_at(address, &key)? == value);

        self.write_account_lock(address)?
            .set_storage(key, value, owner);
        Ok(())
    }
}

impl State {
    /// Get the value of storage at a specific checkpoint.
    #[cfg(test)]
    pub fn checkpoint_storage_at(
        &self, start_checkpoint_index: usize, address: &AddressWithSpace,
        key: &Vec<u8>,
    ) -> DbResult<Option<U256>>
    {
        use super::AccountEntry;
        use cfx_statedb::StateDbExt;
        use primitives::{StorageKey, StorageValue};

        #[derive(Debug)]
        enum ReturnKind {
            OriginalAt,
            SameAsNext,
        }

        let kind = {
            let checkpoints = self.checkpoints.read();

            if start_checkpoint_index >= checkpoints.len() {
                return Ok(None);
            }

            let mut kind = None;

            for checkpoint in checkpoints.iter().skip(start_checkpoint_index) {
                match checkpoint.get(address) {
                    Some(Some(AccountEntry {
                        account: Some(ref account),
                        ..
                    })) => {
                        if let Some(value) = account.cached_storage_at(key) {
                            return Ok(Some(value));
                        } else if account.is_newly_created_contract() {
                            return Ok(Some(U256::zero()));
                        } else {
                            kind = Some(ReturnKind::OriginalAt);
                            break;
                        }
                    }
                    Some(Some(AccountEntry { account: None, .. })) => {
                        return Ok(Some(U256::zero()));
                    }
                    Some(None) => {
                        kind = Some(ReturnKind::OriginalAt);
                        break;
                    }
                    // This key does not have a checkpoint entry.
                    None => {
                        kind = Some(ReturnKind::SameAsNext);
                    }
                }
            }

            kind.expect("start_checkpoint_index is checked to be below checkpoints_len; for loop above must have been executed at least once; it will either early return, or set the kind value to Some; qed")
        };

        match kind {
            ReturnKind::SameAsNext => Ok(Some(self.storage_at(address, key)?)),
            ReturnKind::OriginalAt => {
                match self.db.get::<StorageValue>(
                    StorageKey::new_storage_key(&address.address, key.as_ref())
                        .with_space(address.space),
                )? {
                    Some(storage_value) => Ok(Some(storage_value.value)),
                    None => Ok(Some(U256::zero())),
                }
            }
        }
    }
}
