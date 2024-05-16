// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_parameters::internal_contract_addresses::SYSTEM_STORAGE_ADDRESS;
use rlp::Rlp;

use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_types::{AddressWithSpace, H256, U256};
use primitives::{
    is_default::IsDefault, Account, CodeInfo, DepositList, StorageKey,
    StorageKeyWithSpace, VoteStakeList,
};

use crate::global_params::{GlobalParamKey, InterestRate};

use super::{Result, StateDbGeneric};

pub trait StateDbExt {
    fn get<T>(&self, key: StorageKeyWithSpace) -> Result<Option<T>>
    where T: ::rlp::Decodable;

    fn set<T>(
        &mut self, key: StorageKeyWithSpace, value: &T,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    where
        T: ::rlp::Encodable + IsDefault;

    fn get_account(
        &self, address: &AddressWithSpace,
    ) -> Result<Option<Account>>;

    fn get_code(
        &self, address: &AddressWithSpace, code_hash: &H256,
    ) -> Result<Option<CodeInfo>>;

    fn get_deposit_list(
        &self, address: &AddressWithSpace,
    ) -> Result<Option<DepositList>>;

    fn get_vote_list(
        &self, address: &AddressWithSpace,
    ) -> Result<Option<VoteStakeList>>;

    fn get_system_storage(&self, key: &[u8]) -> Result<U256>;

    fn get_global_param<T: GlobalParamKey>(&self) -> Result<U256>;
    fn set_global_param<T: GlobalParamKey>(
        &mut self, value: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    // This function is used to check whether the db has been initialized when
    // create a state. So we can know the loaded `None` represents "not
    // initialized" or "zero value".
    fn is_initialized(&self) -> Result<bool>;
}

impl StateDbExt for StateDbGeneric {
    fn get<T>(&self, key: StorageKeyWithSpace) -> Result<Option<T>>
    where T: ::rlp::Decodable {
        match self.get_raw(key) {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => Ok(Some(::rlp::decode::<T>(raw.as_ref())?)),
            Err(e) => bail!(e),
        }
    }

    fn set<T>(
        &mut self, key: StorageKeyWithSpace, value: &T,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    where
        T: ::rlp::Encodable + IsDefault,
    {
        if value.is_default() {
            self.delete(key, debug_record)
        } else {
            self.set_raw(
                key,
                ::rlp::encode(value).into_boxed_slice(),
                debug_record,
            )
        }
    }

    fn get_account(
        &self, address: &AddressWithSpace,
    ) -> Result<Option<Account>> {
        match self.get_raw(
            StorageKey::new_account_key(&address.address)
                .with_space(address.space),
        ) {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => Ok(Some(Account::new_from_rlp(
                address.address,
                &Rlp::new(&raw),
            )?)),
            Err(e) => bail!(e),
        }
    }

    fn get_code(
        &self, address: &AddressWithSpace, code_hash: &H256,
    ) -> Result<Option<CodeInfo>> {
        self.get::<CodeInfo>(
            StorageKey::new_code_key(&address.address, code_hash)
                .with_space(address.space),
        )
    }

    fn get_deposit_list(
        &self, address: &AddressWithSpace,
    ) -> Result<Option<DepositList>> {
        address.assert_native();
        self.get::<DepositList>(
            StorageKey::new_deposit_list_key(&address.address)
                .with_native_space(),
        )
    }

    fn get_vote_list(
        &self, address: &AddressWithSpace,
    ) -> Result<Option<VoteStakeList>> {
        address.assert_native();
        self.get::<VoteStakeList>(
            StorageKey::new_vote_list_key(&address.address).with_native_space(),
        )
    }

    fn get_global_param<T: GlobalParamKey>(&self) -> Result<U256> {
        Ok(self.get::<U256>(T::STORAGE_KEY)?.unwrap_or_default())
    }

    fn get_system_storage(&self, key: &[u8]) -> Result<U256> {
        let storage_key = StorageKey::StorageKey {
            address_bytes: SYSTEM_STORAGE_ADDRESS.as_bytes(),
            storage_key: key,
        }
        .with_native_space();
        Ok(self.get::<U256>(storage_key)?.unwrap_or_default())
    }

    fn set_global_param<T: GlobalParamKey>(
        &mut self, value: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()> {
        self.set::<U256>(T::STORAGE_KEY, value, debug_record)
    }

    fn is_initialized(&self) -> Result<bool> {
        let interest_rate_opt = self.get::<U256>(InterestRate::STORAGE_KEY)?;
        Ok(interest_rate_opt.is_some())
    }
}
