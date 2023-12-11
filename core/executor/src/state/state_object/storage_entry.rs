use super::{State, Substate};
use crate::try_loaded;
use cfx_parameters::internal_contract_addresses::SYSTEM_STORAGE_ADDRESS;
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, U256};

impl State {
    // System Storage shares the cache and checkpoint mechanisms with
    // `OverlayAccount` storage entries. Similar to global statistic
    // variables, it represents global variables of the blockchain system,
    // operating without an owner during execution. As such, system storage
    // doesn't generate collateral, nor is it recorded in receipts.

    // While its access performance is slightly lower than global statistics due
    // to the cache and checkpoint mechanism, it benefits code maintainability.
    // New global variables are preferentially stored in system storage.
    pub fn get_system_storage(&self, key: &[u8]) -> DbResult<U256> {
        self.storage_at(&SYSTEM_STORAGE_ADDRESS.with_native_space(), key)
    }

    pub fn set_system_storage(
        &mut self, key: Vec<u8>, value: U256,
    ) -> DbResult<()> {
        // The system storage contract does not have owner, and thus does not
        // require actual storage owner and substate which records ownership
        // changes.
        self.set_storage(
            &SYSTEM_STORAGE_ADDRESS.with_native_space(),
            key,
            value,
            Address::zero(),
            &mut Substate::new(),
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
        owner: Address, substate: &mut Substate,
    ) -> DbResult<()>
    {
        self.write_account_lock(address)?
            .set_storage(&self.db, key, value, owner, substate)?;
        Ok(())
    }

    pub fn is_fresh_storage(
        &self, address: &AddressWithSpace,
    ) -> DbResult<bool> {
        let acc = try_loaded!(self.read_account_lock(address));
        Ok(acc.fresh_storage())
    }
}

#[cfg(test)]
impl State {
    /// Get the value of storage at a specific checkpoint.
    pub fn checkpoint_storage_at(
        &self, start_checkpoint_index: usize, address: &AddressWithSpace,
        key: &Vec<u8>,
    ) -> DbResult<Option<U256>>
    {
        use super::{checkpoints::CheckpointEntry::*, AccountEntry};
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
                match checkpoint.entries().get(address) {
                    Some(Recorded(AccountEntry::Cached(ref account, _))) => {
                        if let Some(value) = account.cached_value_at(key) {
                            return Ok(Some(value));
                        } else if account.is_newly_created_contract() {
                            return Ok(Some(U256::zero()));
                        } else {
                            kind = Some(ReturnKind::OriginalAt);
                            break;
                        }
                    }
                    Some(Recorded(AccountEntry::DbAbsent)) => {
                        return Ok(Some(U256::zero()));
                    }
                    Some(Unchanged) => {
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
