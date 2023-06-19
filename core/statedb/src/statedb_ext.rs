// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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

// pub const ACCUMULATE_INTEREST_RATE_KEY: &'static [u8] =
//     b"accumulate_interest_rate";
// pub const INTEREST_RATE_KEY: &'static [u8] = b"interest_rate";
// pub const TOTAL_BANK_TOKENS_KEY: &'static [u8] = b"total_staking_tokens";
// pub const TOTAL_STORAGE_TOKENS_KEY: &'static [u8] = b"total_storage_tokens";
// pub const TOTAL_TOKENS_KEY: &'static [u8] = b"total_issued_tokens";
// pub const TOTAL_POS_STAKING_TOKENS_KEY: &'static [u8] =
//     b"total_pos_staking_tokens";
// pub const DISTRIBUTABLE_POS_INTEREST_KEY: &'static [u8] =
//     b"distributable_pos_interest";
// pub const LAST_DISTRIBUTE_BLOCK_KEY: &'static [u8] =
// b"last_distribute_block"; pub const TOTAL_EVM_TOKENS_KEY: &'static [u8] =
// b"total_evm_tokens"; pub const USDED_STORAGE_POINTS_KEY: &'static [u8] =
// b"used_storage_points"; pub const CONVERTED_STORAGE_POINTS_KEY: &'static [u8]
// =     b"converted_storage_points_key";
// pub const POW_BASE_REWARD_KEY: &'static [u8] = b"pow_base_reward";

// pub mod params_control_entries {
//     use cfx_parameters::internal_contract_addresses::SYSTEM_STORAGE_ADDRESS;
//     use cfx_types::{Address, U256};
//     use lazy_static::lazy_static;
//     use tiny_keccak::{Hasher, Keccak};
//
//
//
//     fn gen_entry_addresses(
//         start: &U256,
//     ) -> [[[u8; 32]; OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX] {
//         let mut vote_entries =
//             [[[0u8; 32]; OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX];
//         for index in 0..PARAMETER_INDEX_MAX {
//             for opt_index in 0..OPTION_INDEX_MAX {
//                 vote_entries[index][opt_index] =
//                     storage_key_at_index(start, index, opt_index);
//             }
//         }
//         vote_entries
//     }
//
//     fn prefix_and_hash(prefix: u64, data: &[u8]) -> [u8; 32] {
//         let mut hasher = Keccak::v256();
//         hasher.update(&prefix.to_be_bytes());
//         hasher.update(data);
//         let mut hash = [0u8; 32];
//         hasher.finalize(&mut hash);
//         hash
//     }
//
//     #[inline]
//     pub fn start_entry(address: &Address) -> U256 {
//         U256::from_big_endian(&prefix_and_hash(3, address.as_bytes()))
//     }
//
//     pub fn version_entry_key(start: &U256) -> [u8; 32] {
//         let mut entry = [0u8; 32];
//         start.to_big_endian(&mut entry);
//         entry
//     }
//
//     #[inline]
//     pub fn storage_key_at_index(
//         start: &U256, index: usize, opt_index: usize,
//     ) -> [u8; 32] {
//         let mut vote_entry = [0u8; 32];
//         (start + 1 + index * OPTION_INDEX_MAX + opt_index)
//             .to_big_endian(&mut vote_entry);
//         vote_entry
//     }
// }

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

    fn set_global_param<T: GlobalParamKey>(
        &mut self, value: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        self.set::<U256>(T::STORAGE_KEY, value, debug_record)
    }

    fn is_initialized(&self) -> Result<bool> {
        let interest_rate_opt = self.get::<U256>(InterestRate::STORAGE_KEY)?;
        Ok(interest_rate_opt.is_some())
    }
}
