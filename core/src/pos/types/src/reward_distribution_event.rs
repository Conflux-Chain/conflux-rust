use crate::{
    account_address::AccountAddress,
    term_state::{
        BONUS_VOTE_POINTS, COMMITTEE_POINTS, ELECTION_POINTS, LEADER_POINTS,
    },
};
use cfx_types::H256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct VoteCount {
    // The number of rounds that the node becomes the leader.
    pub leader_count: u32,
    // The total number of votes that the node includes as a leader.
    pub included_vote_count: u32,
    // The total number of votes that the node signs in the committed QCs
    // within the term.
    pub vote_count: u32,
}

impl VoteCount {
    pub fn reward_points(&self) -> u64 {
        self.leader_count as u64 * LEADER_POINTS
            + self.included_vote_count as u64 * BONUS_VOTE_POINTS
            + (self.vote_count > 0) as u64 * COMMITTEE_POINTS
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct RewardDistributionEvent {
    pub candidates: Vec<H256>,
    pub elected: BTreeMap<H256, VoteCount>,
}

impl RewardDistributionEvent {
    pub fn rewards(&self) -> impl Iterator<Item = (&H256, u64)> {
        let committee_rewards = self
            .elected
            .iter()
            .map(|(id, vote_count)| (id, vote_count.reward_points()));
        let participate_rewards =
            self.candidates.iter().map(|id| (id, ELECTION_POINTS));
        committee_rewards.chain(participate_rewards)
    }
}
