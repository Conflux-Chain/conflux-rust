// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::convert::TryFrom;

use cfx_statedb::{StateDbExt, params_control_entries::*};
use cfx_types::{Address, U256, U512};

use crate::{
    executive::{
        internal_contract::{
            contracts::params_control::Vote,
            impls::{
                staking::get_vote_power,
            },
        },
        InternalRefContext,
    },
    vm::{self, ActionParams, Error},
};

pub fn cast_vote(
    address: Address, version: u64, votes: Vec<Vote>, params: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()>
{
    // If this is called, `env.number` must be larger than the activation
    // number. And version starts from 1 to tell if an account has ever voted in
    // the first version.
    let current_voting_version = (context.env.number
        - context.spec.cip94_activation_block_number)
        / context.spec.params_dao_vote_period
        + 1;
    if version != current_voting_version {
        bail!(Error::InternalContract(format!(
            "vote version unmatch: current={} voted={}",
            current_voting_version, version
        )));
    }
    let account_start_entry = start_entry(&address);
    let old_version =
        context.storage_at(params, &version_entry_key(&account_start_entry))?;
    let is_new_vote = old_version.as_u64() != version;

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
                let vote_entry = storage_key_at_index(
                    &account_start_entry,
                    index,
                    opt_index,
                );
                let old_vote = if is_new_vote {
                    U256::zero()
                } else {
                    context.storage_at(params, &vote_entry)?
                };
                debug!(
                    "index:{}, opt_index{}, old_vote: {}, new_vote: {}",
                    index, opt_index, old_vote, param_vote[opt_index]
                );
                if old_vote != param_vote[opt_index] {
                    let old_total_votes =
                        context.state.get_params_vote_count(index, opt_index);
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
                    debug!(
                        "old_total_vote: {}, new_total_vote:{}",
                        old_total_votes, new_total_votes
                    );
                    context.state.update_params_vote_count(
                        index,
                        opt_index,
                        new_total_votes,
                    );
                    context.set_storage(
                        params,
                        vote_entry.to_vec(),
                        param_vote[opt_index],
                    )?;
                }
            }
        }
    }
    if is_new_vote {
        context.set_storage(
            params,
            version_entry_key(&account_start_entry).to_vec(),
            U256::from(version),
        )?;
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
pub fn settled_param_vote_count<T: StateDbExt>(
    state: &T,
) -> vm::Result<AllParamsVoteCount> {
    let pow_base_reward = ParamVoteCount {
        unchange: state.get_settled_params_vote_count(
            POW_BASE_REWARD_INDEX as usize,
            OPTION_UNCHANGE_INDEX as usize,
        )?,
        increase: state.get_settled_params_vote_count(
            POW_BASE_REWARD_INDEX as usize,
            OPTION_INCREASE_INDEX as usize,
        )?,
        decrease: state.get_settled_params_vote_count(
            POW_BASE_REWARD_INDEX as usize,
            OPTION_DECREASE_INDEX as usize,
        )?,
    };
    let pos_reward_interest = ParamVoteCount {
        unchange: state.get_settled_params_vote_count(
            POS_REWARD_INTEREST_RATE_INDEX as usize,
            OPTION_UNCHANGE_INDEX as usize,
        )?,
        increase: state.get_settled_params_vote_count(
            POS_REWARD_INTEREST_RATE_INDEX as usize,
            OPTION_INCREASE_INDEX as usize,
        )?,
        decrease: state.get_settled_params_vote_count(
            POS_REWARD_INTEREST_RATE_INDEX as usize,
            OPTION_DECREASE_INDEX as usize,
        )?,
    };
    Ok(AllParamsVoteCount {
        pow_base_reward,
        pos_reward_interest,
    })
}

#[derive(Clone, Copy, Debug, Default)]
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

#[derive(Clone, Copy, Debug, Default)]
pub struct AllParamsVoteCount {
    pub pow_base_reward: ParamVoteCount,
    pub pos_reward_interest: ParamVoteCount,
}
