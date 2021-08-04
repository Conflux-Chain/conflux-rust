use crate::account_address::AccountAddress;
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

#[derive(Clone, Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
pub struct RewardDistributionEvent {
    pub candidates: Vec<AccountAddress>,
    pub elected: BTreeMap<AccountAddress, VoteCount>,
}
