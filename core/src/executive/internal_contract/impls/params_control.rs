// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    executive::{
        internal_contract::{
            contracts::params_control::Vote,
            impls::{
                params_control::entries::{
                    start_entry, storage_key_at_index, OPTION_DECREASE_INDEX,
                    OPTION_INCREASE_INDEX, OPTION_INDEX_MAX,
                    OPTION_UNCHANGE_INDEX, PARAMETER_INDEX_MAX,
                    POS_REWARD_INTEREST_RATE_INDEX, POW_BASE_REWARD_INDEX,
                    TOTAL_VOTES_ENTRIES,
                },
                staking::get_vote_power,
            },
            params_control_internal_entries::SETTLED_TOTAL_VOTES_ENTRIES,
        },
        InternalRefContext,
    },
    observer::{AddressPocket, VmObserve},
    state::{cleanup_mode, State},
    vm::{self, ActionParams, Error, Spec},
};
use cfx_parameters::{
    block::DAO_PARAMETER_VOTE_PERIOD,
    internal_contract_addresses::PARAMS_CONTROL_CONTRACT_ADDRESS,
};
use cfx_state::{state_trait::StateOpsTrait, SubstateTrait};
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, U256, U512,
};
use std::convert::TryFrom;

pub fn cast_vote(
    address: Address, version: u64, votes: Vec<Vote>, params: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()>
{
    // If this is called, `env.number` must be larger than the activation
    // number.
    let current_voting_version = (context.env.number
        - context.spec.cip94_activation_block_number)
        / context.spec.params_dao_vote_period;
    if version != current_voting_version {
        bail!(Error::InternalContract(format!(
            "vote version unmatch: current={} voted={}",
            current_voting_version, version
        )));
    }

    let mut vote_counts =
        [[U256::zero(); OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX];
    for vote in votes {
        if vote.index >= PARAMETER_INDEX_MAX as u16
            || vote.opt_index >= OPTION_INDEX_MAX as u16
        {
            bail!(Error::InternalContract(
                "invalid vote index or opt_index".to_string()
            ));
        }
        // TODO: Do we allow multiple votes for the same index and opt_index?
        vote_counts[vote.index as usize][vote.opt_index as usize] = vote_counts
            [vote.index as usize][vote.opt_index as usize]
            .saturating_add(vote.votes);
    }

    let vote_power = get_vote_power(
        address,
        U256::from(context.env.number),
        context.env.number,
        context.state,
    )?;
    let account_start_entry = start_entry(&address);
    for index in 0..PARAMETER_INDEX_MAX {
        let param_vote = vote_counts[index];
        let total_counts = param_vote[0]
            .saturating_add(param_vote[1])
            .saturating_add(param_vote[2]);
        // TODO: Do we allow cancelling votes by voting with 0 votes?
        // If no vote, we do not need any process.
        if total_counts != U256::zero() {
            if total_counts > vote_power {
                bail!(Error::InternalContract(format!(
                    "not enough vote power: power={} votes={}",
                    vote_power, total_counts
                )));
            }
            for opt_index in 0..OPTION_INDEX_MAX {
                let mut vote_entry = storage_key_at_index(
                    &account_start_entry,
                    index,
                    opt_index,
                );
                let old_vote = context.storage_at(params, &vote_entry)?;
                if old_vote != param_vote[opt_index] {
                    let old_total_votes = context.storage_at(
                        params,
                        &TOTAL_VOTES_ENTRIES[index][opt_index],
                    )?;
                    let new_total_votes = if old_vote > param_vote[opt_index] {
                        let dec = old_vote - param_vote[opt_index];
                        // If total votes are accurate, `old_total_votes` is
                        // larger than `old_vote`.
                        old_total_votes - dec
                    } else if old_vote < param_vote[opt_index] {
                        let inc = param_vote[opt_index] - old_vote;
                        old_total_votes + inc
                    } else {
                        unreachable!("votes changed")
                    };
                    context.state.update_params_vote_count(
                        index,
                        opt_index,
                        new_total_votes,
                    )?;
                    context.set_storage(
                        params,
                        vote_entry.to_vec(),
                        param_vote[opt_index],
                    )?;
                }
            }
        }
    }
    Ok(())
}

pub fn read_vote(
    address: Address, params: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<Vec<Vote>> {
    let mut votes_list = Vec::new();
    let account_start_entry = start_entry(&address);
    for index in 0..PARAMETER_INDEX_MAX {
        for opt_index in 0..OPTION_INDEX_MAX {
            let votes = context.storage_at(
                params,
                &storage_key_at_index(&account_start_entry, index, opt_index),
            )?;
            if votes != U256::zero() {
                votes_list.push(Vote {
                    index: index as u16,
                    opt_index: opt_index as u16,
                    votes,
                })
            }
        }
    }
    Ok(votes_list)
}

/// If the vote counts are not initialized, all counts will be zero, and the
/// parameters will be unchanged.
pub fn next_param_vote_count(state: &State) -> vm::Result<AllParamsVoteCount> {
    let pow_base_reward = ParamVoteCount {
        unchange: state.storage_at(
            &PARAMS_CONTROL_CONTRACT_ADDRESS.with_native_space(),
            &SETTLED_TOTAL_VOTES_ENTRIES[POW_BASE_REWARD_INDEX as usize]
                [OPTION_UNCHANGE_INDEX as usize],
        )?,
        increase: state.storage_at(
            &PARAMS_CONTROL_CONTRACT_ADDRESS.with_native_space(),
            &SETTLED_TOTAL_VOTES_ENTRIES[POW_BASE_REWARD_INDEX as usize]
                [OPTION_INCREASE_INDEX as usize],
        )?,
        decrease: state.storage_at(
            &PARAMS_CONTROL_CONTRACT_ADDRESS.with_native_space(),
            &SETTLED_TOTAL_VOTES_ENTRIES[POW_BASE_REWARD_INDEX as usize]
                [OPTION_DECREASE_INDEX as usize],
        )?,
    };
    let pos_reward_interest = ParamVoteCount {
        unchange: state.storage_at(
            &PARAMS_CONTROL_CONTRACT_ADDRESS.with_native_space(),
            &SETTLED_TOTAL_VOTES_ENTRIES
                [POS_REWARD_INTEREST_RATE_INDEX as usize]
                [OPTION_UNCHANGE_INDEX as usize],
        )?,
        increase: state.storage_at(
            &PARAMS_CONTROL_CONTRACT_ADDRESS.with_native_space(),
            &SETTLED_TOTAL_VOTES_ENTRIES
                [POS_REWARD_INTEREST_RATE_INDEX as usize]
                [OPTION_INCREASE_INDEX as usize],
        )?,
        decrease: state.storage_at(
            &PARAMS_CONTROL_CONTRACT_ADDRESS.with_native_space(),
            &SETTLED_TOTAL_VOTES_ENTRIES
                [POS_REWARD_INTEREST_RATE_INDEX as usize]
                [OPTION_DECREASE_INDEX as usize],
        )?,
    };
    Ok(AllParamsVoteCount {
        pow_base_reward,
        pos_reward_interest,
    })
}

/// Move TOTAL_VOTES_ENTRIES to the settled ones and reset the counts.
/// If this is called for the first time, all counts will be initialized with
/// zeros.
pub fn settle_vote_counts(state: &mut State) -> vm::Result<()> {
    for index in 0..PARAMETER_INDEX_MAX {
        for opt_index in 0..OPTION_INDEX_MAX {
            let vote = state.storage_at(
                &PARAMS_CONTROL_CONTRACT_ADDRESS.with_native_space(),
                &TOTAL_VOTES_ENTRIES[index][opt_index],
            )?;
            state.update_params_vote_count(index, opt_index, U256::zero())?;
            state.update_settled_params_vote_count(index, opt_index, vote)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct ParamVoteCount {
    unchange: U256,
    increase: U256,
    decrease: U256,
}

impl ParamVoteCount {
    pub fn new(unchange: U256, increase: U256, decrease: U256) -> Self {
        Self {
            unchange,
            increase,
            decrease,
        }
    }

    pub fn compute_next_params(&self, old_value: U256) -> U256 {
        // `VoteCount` only counts valid votes, so this will not overflow.
        let total = self.unchange + self.increase + self.decrease;
        if total == U256::zero() {
            // If no one votes, we just keep the value unchanged.
            return old_value;
        }
        let weighted_total =
            self.unchange + self.increase * 2u64 + self.decrease / 2u64;
        let new_value = U512::from(old_value) * U512::from(weighted_total)
            / U512::from(total);
        U256::try_from(new_value).unwrap()
    }
}

#[derive(Debug)]
pub struct AllParamsVoteCount {
    pub pow_base_reward: ParamVoteCount,
    pub pos_reward_interest: ParamVoteCount,
}

pub mod entries {
    use super::*;
    use cfx_types::H256;
    use tiny_keccak::{Hasher, Keccak};

    pub type StorageEntryKey = Vec<u8>;

    pub const CURRENT_TOTAL_VOTES_KEY: &'static [u8] = b"current_total_votes";
    pub const NEXT_TOTAL_VOTES_KEY: &'static [u8] = b"next_total_votes";

    pub const POW_BASE_REWARD_INDEX: u8 = 0;
    pub const POS_REWARD_INTEREST_RATE_INDEX: u8 = 1;
    pub const PARAMETER_INDEX_MAX: usize = 2;

    pub const OPTION_UNCHANGE_INDEX: u8 = 0;
    pub const OPTION_INCREASE_INDEX: u8 = 1;
    pub const OPTION_DECREASE_INDEX: u8 = 2;
    pub const OPTION_INDEX_MAX: usize = 3;

    lazy_static! {
        pub static ref TOTAL_VOTES_START_ENTRY: U256 =
            start_entry(&*PARAMS_CONTROL_CONTRACT_ADDRESS);
        pub static ref TOTAL_VOTES_ENTRIES: [[[u8; 32]; OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX] =
            gen_entry_addresses(0);
        pub static ref SETTLED_TOTAL_VOTES_ENTRIES: [[[u8; 32]; OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX] =
            gen_entry_addresses(PARAMETER_INDEX_MAX * OPTION_INDEX_MAX);
    }

    fn gen_entry_addresses(
        offset: usize,
    ) -> [[[u8; 32]; OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX] {
        let mut vote_entries =
            [[[0u8; 32]; OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX];
        for index in 0..PARAMETER_INDEX_MAX {
            for opt_index in 0..OPTION_INDEX_MAX {
                let mut entry = [0u8; 32];
                vote_entries[index][opt_index] = storage_key_at_index(
                    &(*TOTAL_VOTES_START_ENTRY + offset),
                    index,
                    opt_index,
                );
            }
        }
        vote_entries
    }

    fn prefix_and_hash(prefix: u64, data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        hasher.update(&prefix.to_be_bytes());
        hasher.update(data);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        hash
    }

    #[inline]
    pub fn start_entry(address: &Address) -> U256 {
        U256::from_big_endian(&prefix_and_hash(3, address.as_bytes()))
    }

    #[inline]
    pub fn storage_key_at_index(
        start: &U256, index: usize, opt_index: usize,
    ) -> [u8; 32] {
        let mut vote_entry = [0u8; 32];
        (start + index * OPTION_INDEX_MAX + opt_index)
            .to_big_endian(&mut vote_entry);
        vote_entry
    }
}
