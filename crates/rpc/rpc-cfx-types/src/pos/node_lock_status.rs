use cfx_types::U64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NodeLockStatus {
    pub in_queue: Vec<VotePowerState>,
    pub locked: U64,
    pub out_queue: Vec<VotePowerState>,
    pub unlocked: U64,

    // Equals to the summation of in_queue + locked
    pub available_votes: U64,

    pub force_retired: Option<U64>,
    // If the staking is forfeited, the forfeited value will never be unlocked.
    pub forfeited: U64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VotePowerState {
    pub end_block_number: U64,
    pub power: U64,
}
