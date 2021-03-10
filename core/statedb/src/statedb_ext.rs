// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait StateDbExt {
    fn get<T>(&self, key: StorageKey) -> Result<Option<T>>
    where
        T: ::rlp::Decodable;

    fn set<T>(
        &mut self, key: StorageKey, value: &T,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    where
        T: ::rlp::Encodable + IsDefault;

    fn get_account(&self, address: &Address) -> Result<Option<Account>>;

    fn get_code(
        &self, address: &Address, code_hash: &H256,
    ) -> Result<Option<CodeInfo>>;

    fn get_deposit_list(
        &self, address: &Address,
    ) -> Result<Option<DepositList>>;

    fn get_vote_list(&self, address: &Address)
        -> Result<Option<VoteStakeList>>;

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

    // This function is used to check whether the db has been initialized when
    // create a state. So we can know the loaded `None` represents "not
    // initialized" or "zero value".
    fn is_initialized(&self) -> Result<bool>;
}

pub const ACCUMULATE_INTEREST_RATE_KEY: &'static [u8] =
    b"accumulate_interest_rate";
pub const INTEREST_RATE_KEY: &'static [u8] = b"interest_rate";
const TOTAL_BANK_TOKENS_KEY: &'static [u8] = b"total_staking_tokens";
const TOTAL_STORAGE_TOKENS_KEY: &'static [u8] = b"total_storage_tokens";
const TOTAL_TOKENS_KEY: &'static [u8] = b"total_issued_tokens";

impl<StateDbStorage: StorageStateTrait> StateDbExt
    for StateDbGeneric<StateDbStorage>
{
    fn get<T>(&self, key: StorageKey) -> Result<Option<T>>
    where
        T: ::rlp::Decodable,
    {
        match self.get_raw(key) {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => Ok(Some(::rlp::decode::<T>(raw.as_ref())?)),
            Err(e) => bail!(e),
        }
    }

    fn set<T>(
        &mut self, key: StorageKey, value: &T,
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

    fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        match self.get_raw(StorageKey::new_account_key(address)) {
            Ok(None) => Ok(None),
            Ok(Some(raw)) => {
                Ok(Some(Account::new_from_rlp(*address, &Rlp::new(&raw))?))
            }
            Err(e) => bail!(e),
        }
    }

    fn get_code(
        &self, address: &Address, code_hash: &H256,
    ) -> Result<Option<CodeInfo>> {
        self.get::<CodeInfo>(StorageKey::new_code_key(address, code_hash))
    }

    fn get_deposit_list(
        &self, address: &Address,
    ) -> Result<Option<DepositList>> {
        self.get::<DepositList>(StorageKey::new_deposit_list_key(address))
    }

    fn get_vote_list(
        &self, address: &Address,
    ) -> Result<Option<VoteStakeList>> {
        self.get::<VoteStakeList>(StorageKey::new_vote_list_key(address))
    }

    fn get_annual_interest_rate(&self) -> Result<U256> {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            INTEREST_RATE_KEY,
        );
        let interest_rate_opt = self.get::<U256>(interest_rate_key)?;
        Ok(interest_rate_opt.unwrap_or_default())
    }

    fn set_annual_interest_rate(
        &mut self, interest_rate: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()> {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            INTEREST_RATE_KEY,
        );
        self.set::<U256>(interest_rate_key, interest_rate, debug_record)
    }

    fn get_accumulate_interest_rate(&self) -> Result<U256> {
        let acc_interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            ACCUMULATE_INTEREST_RATE_KEY,
        );
        let acc_interest_rate_opt = self.get::<U256>(acc_interest_rate_key)?;
        Ok(acc_interest_rate_opt.unwrap_or_default())
    }

    fn set_accumulate_interest_rate(
        &mut self, accumulate_interest_rate: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()> {
        let acc_interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            ACCUMULATE_INTEREST_RATE_KEY,
        );
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
        );
        let total_issued_tokens_opt =
            self.get::<U256>(total_issued_tokens_key)?;
        Ok(total_issued_tokens_opt.unwrap_or_default())
    }

    fn set_total_issued_tokens(
        &mut self, total_issued_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()> {
        let total_issued_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_TOKENS_KEY,
        );
        self.set::<U256>(
            total_issued_tokens_key,
            total_issued_tokens,
            debug_record,
        )
    }

    fn get_total_staking_tokens(&self) -> Result<U256> {
        let total_staking_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_BANK_TOKENS_KEY,
        );
        let total_staking_tokens_opt =
            self.get::<U256>(total_staking_tokens_key)?;
        Ok(total_staking_tokens_opt.unwrap_or_default())
    }

    fn set_total_staking_tokens(
        &mut self, total_staking_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()> {
        let total_staking_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_BANK_TOKENS_KEY,
        );
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
        );
        let total_storage_tokens_opt =
            self.get::<U256>(total_storage_tokens_key)?;
        Ok(total_storage_tokens_opt.unwrap_or_default())
    }

    fn set_total_storage_tokens(
        &mut self, total_storage_tokens: &U256,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()> {
        let total_storage_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            TOTAL_STORAGE_TOKENS_KEY,
        );
        self.set::<U256>(
            total_storage_tokens_key,
            total_storage_tokens,
            debug_record,
        )
    }

    fn is_initialized(&self) -> Result<bool> {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            INTEREST_RATE_KEY,
        );
        let interest_rate_opt = self.get::<U256>(interest_rate_key)?;
        Ok(interest_rate_opt.is_some())
    }
}

use super::{Result, StateDbGeneric};
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::internal_contract_addresses::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS;
use cfx_storage::StorageStateTrait;
use cfx_types::{Address, H256, U256};
use primitives::{
    is_default::IsDefault, Account, CodeInfo, DepositList, StorageKey,
    VoteStakeList,
};
use rlp::Rlp;
