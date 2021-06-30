use async_trait::async_trait;
use cfx_types::H256;
use diem_types::{
    account_address::AccountAddress,
    validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey},
};
use std::collections::HashMap;

#[async_trait]
pub trait PowInterface: Send + Sync {
    // TODO(lpl): Wait for new pivot decision.
    async fn next_pivot_decision(
        &self, parent_decision: H256,
    ) -> Option<(u64, H256)>;

    fn validate_proposal_pivot_decision(
        &self, parent_decision: H256, me_decision: H256,
    ) -> bool;

    async fn get_staking_events(
        &self, parent_decision: H256, me_decision: H256,
    ) -> Vec<StakingEvents>;
}

pub enum StakingEvents {
    Register((AccountAddress, ConsensusPublicKey, ConsensusVRFPublicKey)),
    IncreaseStake((AccountAddress, u64)),
}
