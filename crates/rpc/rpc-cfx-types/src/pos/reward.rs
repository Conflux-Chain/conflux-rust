// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::RpcAddress;
use cfx_types::{H256, U256};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reward {
    //
    pub pos_address: H256,
    //
    pub pow_address: RpcAddress,
    //
    pub reward: U256,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoSEpochReward {
    //
    pub pow_epoch_hash: H256,
    //
    pub account_rewards: Vec<Reward>,
}
