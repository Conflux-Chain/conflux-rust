use async_trait::async_trait;
use cfx_types::H256;
use diem_types::account_address::AccountAddress;
use std::{collections::HashMap, sync::Arc};

#[async_trait]
pub trait PowInterface: Send + Sync {
    // TODO(lpl): Wait for new pivot decision.
    async fn next_pivot_decision(&self, parent_decision: H256) -> Option<H256>;

    async fn validate_proposal_pivot_decision(
        &self, parent_decision: H256, me_decision: H256,
    ) -> bool;

    /// Return the map from committee addresses to their voting power.
    async fn get_committee_candidates(&self) -> HashMap<AccountAddress, u64>;
}
