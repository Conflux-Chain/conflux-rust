// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use anyhow::Result;
use async_trait::async_trait;
use cfx_types::H256;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait PowInterface: Send + Sync {
    // TODO(lpl): Wait for new pivot decision.
    async fn next_pivot_decision(
        &self, parent_decision: H256,
    ) -> Option<(u64, H256)>;

    fn validate_proposal_pivot_decision(
        &self, parent_decision: H256, me_decision: H256,
    ) -> bool;

    fn get_staking_events(
        &self, parent_height: u64, me_height: u64, parent_decision: H256,
        me_decision: H256,
    ) -> Result<Vec<StakingEvent>>;

    async fn wait_for_initialization(&self, last_decision: H256);

    fn is_normal_phase(&self) -> bool;
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StakingEvent {
    /// (address, bls_public_key, vrf_public_key)
    Register(H256, Vec<u8>, Vec<u8>),
    /// (address, updated_voting_power)
    IncreaseStake(H256, u64),
    /// (address, unlock_voting_power)
    Retire(H256, u64),
}

/// This is just used to execute PoS genesis, where pow_handler will not be
/// used.
pub struct FakePowHandler {}

#[async_trait]
impl PowInterface for FakePowHandler {
    async fn next_pivot_decision(
        &self, _parent_decision: H256,
    ) -> Option<(u64, H256)> {
        todo!()
    }

    fn validate_proposal_pivot_decision(
        &self, _parent_decision: H256, _me_decision: H256,
    ) -> bool {
        todo!()
    }

    fn get_staking_events(
        &self, _parent_height: u64, _me_height: u64, _parent_decision: H256,
        _me_decision: H256,
    ) -> Result<Vec<StakingEvent>> {
        todo!()
    }

    async fn wait_for_initialization(&self, _last_decision: H256) { todo!() }

    fn is_normal_phase(&self) -> bool { todo!() }
}
