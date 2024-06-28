// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use cfx_types::H256;

use crate::term_state::{
    bonus_vote_points, leader_points, COMMITTEE_POINTS, ELECTION_POINTS,
};

#[derive(Clone, Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct VoteCount {
    // The number of rounds that the node becomes the leader.
    pub leader_count: u32,
    // The total number of votes that the node includes as a leader.
    pub included_vote_count: u64,
    // Total vote
    pub total_votes: u64,
    // The total number of votes that the node signs in the committed QCs
    // within the term.
    pub vote_count: u64,
}

impl VoteCount {
    pub fn reward_points(&self, view: u64) -> u64 {
        if self.vote_count == 0 {
            return 0;
        }
        self.leader_count as u64 * leader_points(view)
            + self.included_vote_count * bonus_vote_points(view)
            + self.total_votes * COMMITTEE_POINTS
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct RewardDistributionEventV2 {
    pub candidates: BTreeMap<H256, u64>,
    pub elected: BTreeMap<H256, VoteCount>,
    pub view: u64,
}

impl RewardDistributionEventV2 {
    pub fn rewards(&self) -> impl Iterator<Item = (&H256, u64)> {
        let view = self.view;
        let committee_rewards = self
            .elected
            .iter()
            .map(move |(id, vote_count)| (id, vote_count.reward_points(view)));
        let participate_rewards = self
            .candidates
            .iter()
            .map(|(id, cnt)| (id, ELECTION_POINTS * cnt));
        committee_rewards.chain(participate_rewards)
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct RewardDistributionEventV1 {
    pub candidates: BTreeMap<H256, u64>,
    pub elected: BTreeMap<H256, VoteCount>,
}

impl From<RewardDistributionEventV1> for RewardDistributionEventV2 {
    fn from(value: RewardDistributionEventV1) -> Self {
        Self {
            candidates: value.candidates,
            elected: value.elected,
            view: 0,
        }
    }
}
