use std::sync::Arc;
use crate::ConsensusGraph;
use cfx_types::H256;
use diem_types::account_address::AccountAddress;
use std::collections::HashMap;

pub const POS_TERM_EPOCHS: u64 = 60;

pub trait PowInterface {
    // TODO(lpl): Wait for new pivot decision.
    fn latest_pivot_decision(&self) -> H256;

    fn validate_proposal_pivot_decision(&self, parent_decision: &H256, me_decision: &H256) -> bool;

    /// Return the map from committee addresses to their voting power.
    fn get_committee_candidates(&self) -> HashMap<AccountAddress, u64>;
}

pub struct PowHandler {
    pow_consensus: Arc<ConsensusGraph>,
}

impl PowInterface for PowHandler {
    fn latest_pivot_decision(&self) -> Option<H256> {
        let inner = self.pow_consensus.inner.read();
        let best_epoch = inner.best_epoch_number();
        if best_epoch >= POS_TERM_EPOCHS {
            Some(inner.get_pivot_hash_from_epoch_number(best_epoch / POS_TERM_EPOCHS * POS_TERM_EPOCHS).expect("best epoch in memory"))
        } else {
            None
        }
    }

    fn validate_proposal_pivot_decision(&self, parent_decision: &H256, me_decision: &H256) -> bool {
        self.pow_consensus.inner.read().is_ancestor_of(parent_decision, me_decision)
    }

    fn get_committee_candidates(&self) -> HashMap<AccountAddress, u64> {
        todo!("Implement committee change later")
    }
}