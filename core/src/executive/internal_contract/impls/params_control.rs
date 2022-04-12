// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    executive::{
        internal_contract::{
            contracts::params_control::Vote,
            impls::{
                params_control::entries::{
                    start_entry, storage_key_at_index, OPTION_INDEX_MAX,
                    PARAMETER_INDEX_MAX, TOTAL_VOTES_ENTRIES,
                },
                staking::get_vote_power,
            },
        },
        InternalRefContext,
    },
    observer::{AddressPocket, VmObserve},
    state::cleanup_mode,
    vm::{self, ActionParams, Error, Spec},
};
use cfx_parameters::{
    block::DAO_PARAMETER_VOTE_PERIOD,
    internal_contract_addresses::PARAMS_CONTROL_CONTRACT_ADDRESS,
};
use cfx_state::{state_trait::StateOpsTrait, SubstateTrait};
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, U256,
};

/// Implementation of `set_admin(address,address)`.
/// The input should consist of 20 bytes `contract_address` + 20 bytes
/// `new_admin_address`
pub fn cast_vote(
    address: Address, version: u64, votes: Vec<Vote>, params: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()>
{
    // If this is called, `env.number` must be larger than the activation
    // number.
    let current_voting_version = (context.env.number
        - context.spec.cip94_activation_block_number)
        / DAO_PARAMETER_VOTE_PERIOD;
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
                    context.set_storage(
                        params,
                        TOTAL_VOTES_ENTRIES[index][opt_index].to_vec(),
                        new_total_votes,
                    );
                    context.set_storage(
                        params,
                        vote_entry.to_vec(),
                        param_vote[opt_index],
                    );
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

pub mod entries {
    use super::*;
    use cfx_types::H256;
    use tiny_keccak::{Hasher, Keccak};

    pub type StorageEntryKey = Vec<u8>;

    pub const CURRENT_TOTAL_VOTES_KEY: &'static [u8] = b"current_total_votes";
    pub const NEXT_TOTAL_VOTES_KEY: &'static [u8] = b"next_total_votes";

    pub const POW_BASE_REWARD_INDEX: u8 = 0;
    pub const POS_BASE_REWARD_INTEREST_RATE_INDEX: u8 = 1;
    pub const PARAMETER_INDEX_MAX: usize = 2;

    pub const OPTION_UNCHANGE_INDEX: u8 = 0;
    pub const OPTION_INCREASE_INDEX: u8 = 1;
    pub const OPTION_DECREASE_INDEX: u8 = 2;
    pub const OPTION_INDEX_MAX: usize = 3;

    lazy_static! {
        pub static ref TOTAL_VOTES_START_ENTRY: U256 =
            start_entry(&*PARAMS_CONTROL_CONTRACT_ADDRESS);
        pub static ref TOTAL_VOTES_ENTRIES: [[[u8; 32]; OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX] = {
            let mut vote_entries =
                [[[0u8; 32]; OPTION_INDEX_MAX]; PARAMETER_INDEX_MAX];
            for index in 0..PARAMETER_INDEX_MAX {
                for opt_index in 0..OPTION_INDEX_MAX {
                    let mut entry = [0u8; 32];
                    vote_entries[index][opt_index] = storage_key_at_index(
                        &*TOTAL_VOTES_START_ENTRY,
                        index,
                        opt_index,
                    );
                }
            }
            vote_entries
        };
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
