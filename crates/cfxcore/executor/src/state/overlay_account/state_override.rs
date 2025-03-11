use super::{AccountEntry, OverlayAccount};
use cfx_rpc_eth_types::{AccountOverride, AccountStateOverrideMode};
use cfx_types::{AddressWithSpace, Space, H256, U256};
use primitives::{Account, StorageValue};
use std::{collections::HashMap, sync::Arc};

impl AccountEntry {
    pub fn from_loaded_with_override(
        address: &AddressWithSpace, account: Option<Account>,
        acc_overrides: &AccountOverride,
    ) -> Self {
        let acc = account.unwrap_or_else(|| Account::new_empty(address));
        AccountEntry::Cached(
            OverlayAccount::from_loaded_with_override(
                address,
                acc,
                acc_overrides,
            ),
            true,
        )
    }
}

impl OverlayAccount {
    pub fn from_loaded_with_override(
        address: &AddressWithSpace, account: Account,
        acc_overrides: &AccountOverride,
    ) -> Self {
        let mut acc = Self::from_loaded(address, account);

        if let Some(balance) = acc_overrides.balance {
            let curr_balance = *acc.balance();
            if curr_balance > U256::zero() {
                acc.sub_balance(&curr_balance);
            }
            acc.add_balance(&balance);
        }

        if let Some(nonce) = acc_overrides.nonce {
            acc.set_nonce(&U256::from(nonce.as_u64()));
        }

        if let Some(code) = acc_overrides.code.as_ref() {
            acc.init_code(code.clone(), address.address);
        }

        match &acc_overrides.state {
            AccountStateOverrideMode::State(state_override) => {
                acc.override_storage_read_cache(state_override, true);
            }
            AccountStateOverrideMode::Diff(diff) => {
                acc.override_storage_read_cache(diff, false);
            }
            AccountStateOverrideMode::None => {}
        }

        if acc_overrides.move_precompile_to.is_some() {
            // TODO: impl move precompile to logic
        }

        acc
    }

    fn override_storage_read_cache(
        &mut self, account_storage: &HashMap<H256, H256>,
        complete_override: bool,
    ) {
        assert!(self.storage_write_checkpoint.is_none());

        self.storage_overrided = complete_override;

        let read_cache = Arc::get_mut(&mut self.storage_read_cache)
            .expect("override should happen when no checkpoint")
            .get_mut();
        for (key, value) in account_storage {
            let key = key.as_bytes().to_vec();
            let value = U256::from_big_endian(value.as_bytes());
            let owner = if self.address.space == Space::Native {
                Some(self.address.address)
            } else {
                None
            };
            let storage_value = StorageValue { owner, value };
            read_cache.insert(key, storage_value);
        }
    }
}
