// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use rlp::Rlp;

use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::internal_contract_addresses::{
    PARAMS_CONTROL_CONTRACT_ADDRESS, STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
};
use cfx_types::{AddressWithSpace, H256, U256};
use primitives::{
    is_default::IsDefault, Account, CodeInfo, DepositList, StorageKey,
    StorageKeyWithSpace, VoteStakeList,
};

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

    fn get_annual_interest_rate(&self) -> Result<U256>;
    fn set_annual_interest_rate(
        &mut self, interest_rate: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_accumulate_interest_rate(&self) -> Result<U256>;
    fn set_accumulate_interest_rate(
        &mut self, accumulate_interest_rate: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_total_issued_tokens(&self) -> Result<U256>;
    fn set_total_issued_tokens(
        &mut self, total_issued_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_total_evm_tokens(&self) -> Result<U256>;
    fn set_total_evm_tokens(
        &mut self, total_staking_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_used_storage_points(&self) -> Result<U256>;
    fn set_used_storage_points(
        &mut self, used_storage_points: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_converted_storage_points(&self) -> Result<U256>;
    fn set_converted_storage_points(
        &mut self, converted_storage_points: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_total_staking_tokens(&self) -> Result<U256>;
    fn set_total_staking_tokens(
        &mut self, total_staking_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_total_storage_tokens(&self) -> Result<U256>;
    fn set_total_storage_tokens(
        &mut self, total_storage_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_total_pos_staking_tokens(&self) -> Result<U256>;
    fn set_total_pos_staking_tokens(
        &mut self, total_pos_staking_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_distributable_pos_interest(&self) -> Result<U256>;
    fn set_distributable_pos_interest(
        &mut self, distributable_pos_interest: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_last_distribute_block(&self) -> Result<u64>;
    fn set_last_distribute_block(
        &mut self, last_distribute_block: u64,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    fn get_pow_base_reward(&self) -> Result<Option<U256>>;
    fn set_pow_base_reward(
        &mut self, reward: U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>;

    // This function is used to check whether the db has been initialized when
    // create a state. So we can know the loaded `None` represents "not
    // initialized" or "zero value".
    fn is_initialized(&self) -> Result<bool>;
}

pub const ACCUMULATE_INTEREST_RATE_KEY: &'static [u8] =
    b"accumulate_interest_rate";
pub const INTEREST_RATE_KEY: &'static [u8] = b"interest_rate";
pub const TOTAL_BANK_TOKENS_KEY: &'static [u8] = b"total_staking_tokens";
pub const TOTAL_STORAGE_TOKENS_KEY: &'static [u8] = b"total_storage_tokens";
pub const TOTAL_TOKENS_KEY: &'static [u8] = b"total_issued_tokens";
pub const TOTAL_POS_STAKING_TOKENS_KEY: &'static [u8] =
    b"total_pos_staking_tokens";
pub const DISTRIBUTABLE_POS_INTEREST_KEY: &'static [u8] =
    b"distributable_pos_interest";
pub const LAST_DISTRIBUTE_BLOCK_KEY: &'static [u8] = b"last_distribute_block";
pub const TOTAL_EVM_TOKENS_KEY: &'static [u8] = b"total_evm_tokens";
pub const USDED_STORAGE_POINTS_KEY: &'static [u8] = b"used_storage_points";
pub const CONVERTED_STORAGE_POINTS_KEY: &'static [u8] =
    b"converted_storage_points_key";
pub const POW_BASE_REWARD_KEY: &'static [u8] = b"pow_base_reward";

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

    fn get_annual_interest_rate(&self) -> Result<U256> {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            INTEREST_RATE_KEY,
        )
        .with_native_space();
        let interest_rate_opt = self.get::<U256>(interest_rate_key)?;
        Ok(interest_rate_opt.unwrap_or_default())
    }

    fn set_annual_interest_rate(
        &mut self, interest_rate: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            INTEREST_RATE_KEY,
        )
        .with_native_space();
        self.set::<U256>(interest_rate_key, interest_rate, debug_record)
    }

    fn get_accumulate_interest_rate(&self) -> Result<U256> {
        let acc_interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            ACCUMULATE_INTEREST_RATE_KEY,
        )
        .with_native_space();
        let acc_interest_rate_opt = self.get::<U256>(acc_interest_rate_key)?;
        Ok(acc_interest_rate_opt.unwrap_or_default())
    }

    fn set_accumulate_interest_rate(
        &mut self, accumulate_interest_rate: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let acc_interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            ACCUMULATE_INTEREST_RATE_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            acc_interest_rate_key,
            accumulate_interest_rate,
            debug_record,
        )
    }

    fn get_total_issued_tokens(&self) -> Result<U256> {
        let total_issued_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_TOKENS_KEY,
        )
        .with_native_space();
        let total_issued_tokens_opt =
            self.get::<U256>(total_issued_tokens_key)?;
        Ok(total_issued_tokens_opt.unwrap_or_default())
    }

    fn set_total_issued_tokens(
        &mut self, total_issued_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let total_issued_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_TOKENS_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            total_issued_tokens_key,
            total_issued_tokens,
            debug_record,
        )
    }

    fn get_total_evm_tokens(&self) -> Result<U256> {
        let total_evm_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_EVM_TOKENS_KEY,
        )
        .with_native_space();
        let total_evm_tokens_opt = self.get::<U256>(total_evm_tokens_key)?;
        Ok(total_evm_tokens_opt.unwrap_or_default())
    }

    fn set_total_evm_tokens(
        &mut self, total_evm_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let total_evm_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_EVM_TOKENS_KEY,
        )
        .with_native_space();
        self.set::<U256>(total_evm_tokens_key, total_evm_tokens, debug_record)
    }

    fn get_used_storage_points(&self) -> Result<U256> {
        let used_storage_points_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            USDED_STORAGE_POINTS_KEY,
        )
        .with_native_space();
        let total_evm_tokens_opt = self.get::<U256>(used_storage_points_key)?;
        Ok(total_evm_tokens_opt.unwrap_or_default())
    }

    fn set_used_storage_points(
        &mut self, used_storage_points: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let used_storage_points_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            USDED_STORAGE_POINTS_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            used_storage_points_key,
            used_storage_points,
            debug_record,
        )
    }

    fn get_converted_storage_points(&self) -> Result<U256> {
        let converted_storage_points_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            CONVERTED_STORAGE_POINTS_KEY,
        )
        .with_native_space();
        let total_evm_tokens_opt =
            self.get::<U256>(converted_storage_points_key)?;
        Ok(total_evm_tokens_opt.unwrap_or_default())
    }

    fn set_converted_storage_points(
        &mut self, converted_storage_points: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let converted_storage_points_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            CONVERTED_STORAGE_POINTS_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            converted_storage_points_key,
            converted_storage_points,
            debug_record,
        )
    }

    fn get_total_staking_tokens(&self) -> Result<U256> {
        let total_staking_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_BANK_TOKENS_KEY,
        )
        .with_native_space();
        let total_staking_tokens_opt =
            self.get::<U256>(total_staking_tokens_key)?;
        Ok(total_staking_tokens_opt.unwrap_or_default())
    }

    fn set_total_staking_tokens(
        &mut self, total_staking_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let total_staking_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_BANK_TOKENS_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            total_staking_tokens_key,
            total_staking_tokens,
            debug_record,
        )
    }

    fn get_total_storage_tokens(&self) -> Result<U256> {
        let total_storage_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_STORAGE_TOKENS_KEY,
        )
        .with_native_space();
        let total_storage_tokens_opt =
            self.get::<U256>(total_storage_tokens_key)?;
        Ok(total_storage_tokens_opt.unwrap_or_default())
    }

    fn set_total_storage_tokens(
        &mut self, total_storage_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let total_storage_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_STORAGE_TOKENS_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            total_storage_tokens_key,
            total_storage_tokens,
            debug_record,
        )
    }

    fn get_total_pos_staking_tokens(&self) -> Result<U256> {
        let total_pos_staking_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_POS_STAKING_TOKENS_KEY,
        )
        .with_native_space();
        let total_pos_staking_tokens_opt =
            self.get::<U256>(total_pos_staking_tokens_key)?;
        Ok(total_pos_staking_tokens_opt.unwrap_or_default())
    }

    fn set_total_pos_staking_tokens(
        &mut self, total_pos_staking_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let total_pos_staking_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_POS_STAKING_TOKENS_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            total_pos_staking_tokens_key,
            total_pos_staking_tokens,
            debug_record,
        )
    }

    fn get_distributable_pos_interest(&self) -> Result<U256> {
        let distributable_pos_interest_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            DISTRIBUTABLE_POS_INTEREST_KEY,
        )
        .with_native_space();
        let distributable_pos_interest_opt =
            self.get::<U256>(distributable_pos_interest_key)?;
        Ok(distributable_pos_interest_opt.unwrap_or_default())
    }

    fn set_distributable_pos_interest(
        &mut self, distributable_pos_interest: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let distributable_pos_interest_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            DISTRIBUTABLE_POS_INTEREST_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            distributable_pos_interest_key,
            distributable_pos_interest,
            debug_record,
        )
    }

    fn get_last_distribute_block(&self) -> Result<u64> {
        let last_distribute_block_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            LAST_DISTRIBUTE_BLOCK_KEY,
        )
        .with_native_space();
        let last_distribute_block_opt =
            self.get::<U256>(last_distribute_block_key)?;
        Ok(last_distribute_block_opt.unwrap_or_default().low_u64())
    }

    fn set_last_distribute_block(
        &mut self, last_distribute_block: u64,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let last_distribute_block_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            LAST_DISTRIBUTE_BLOCK_KEY,
        )
        .with_native_space();
        self.set::<U256>(
            last_distribute_block_key,
            &U256::from(last_distribute_block),
            debug_record,
        )
    }

    fn get_pow_base_reward(&self) -> Result<Option<U256>> {
        let pow_base_reward_key = StorageKey::new_storage_key(
            &PARAMS_CONTROL_CONTRACT_ADDRESS,
            POW_BASE_REWARD_KEY,
        )
        .with_native_space();
        let pow_base_reward_opt = self.get::<U256>(pow_base_reward_key)?;
        Ok(pow_base_reward_opt)
    }

    fn set_pow_base_reward(
        &mut self, reward: U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        let pow_base_reward_key = StorageKey::new_storage_key(
            &PARAMS_CONTROL_CONTRACT_ADDRESS,
            POW_BASE_REWARD_KEY,
        )
        .with_native_space();
        self.set::<U256>(pow_base_reward_key, &reward, debug_record)
    }

    fn is_initialized(&self) -> Result<bool> {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            INTEREST_RATE_KEY,
        )
        .with_native_space();
        let interest_rate_opt = self.get::<U256>(interest_rate_key)?;
        Ok(interest_rate_opt.is_some())
    }
}
