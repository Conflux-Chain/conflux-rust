use crate::ConsensusGraph;
use cfx_types::H256;
use diem_types::account_address::AccountAddress;
use futures::{channel::oneshot, executor::block_on};
use std::{collections::HashMap, sync::Arc};
use tokio::runtime::Handle;

pub const POS_TERM_EPOCHS: u64 = 60;

pub trait PowInterface {
    // TODO(lpl): Wait for new pivot decision.
    async fn latest_pivot_decision(&self) -> H256;

    async fn validate_proposal_pivot_decision(
        &self, parent_decision: &H256, me_decision: &H256,
    ) -> bool;

    /// Return the map from committee addresses to their voting power.
    async fn get_committee_candidates(&self) -> HashMap<AccountAddress, u64>;
}

pub struct PowHandler {
    executor: Handle,
    pow_consensus: Arc<ConsensusGraph>,
}

impl PowHandler {
    fn latest_pivot_decision_impl(&self) -> Option<H256> {
        let inner = self.pow_consensus.inner.read();
        let best_epoch = inner.best_epoch_number();
        if best_epoch >= POS_TERM_EPOCHS {
            Some(
                inner
                    .get_pivot_hash_from_epoch_number(
                        best_epoch / POS_TERM_EPOCHS * POS_TERM_EPOCHS,
                    )
                    .expect("best epoch in memory"),
            )
        } else {
            None
        }
    }

    fn validate_proposal_pivot_decision_impl(
        &self, parent_decision: &H256, me_decision: &H256,
    ) -> bool {
        self.pow_consensus
            .inner
            .read()
            .is_ancestor_of(parent_decision, me_decision)
    }

    fn get_committee_candidates_impl(&self) -> HashMap<AccountAddress, u64> {
        todo!("Implement committee change later")
    }
}

impl PowInterface for PowHandler {
    async fn latest_pivot_decision(&self) -> H256 {
        let (callback, cb_receiver) = oneshot::channel();
        self.executor.spawn(async {
            let r = self.latest_pivot_decision_impl();
            callback.send(r);
        });
        block_on(async move { cb_receiver.await? })
    }

    async fn validate_proposal_pivot_decision(
        &self, parent_decision: &H256, me_decision: &H256,
    ) -> bool {
        let (callback, cb_receiver) = oneshot::channel();
        self.executor.spawn(async {
            let r = self.validate_proposal_pivot_decision_impl(
                parent_decision,
                me_decision,
            );
            callback.send(r);
        });
        block_on(async move { cb_receiver.await? })
    }

    async fn get_committee_candidates(&self) -> HashMap<AccountAddress, u64> {
        let (callback, cb_receiver) = oneshot::channel();
        self.executor.spawn(async {
            let r = self.get_committee_candidates_impl();
            callback.send(r);
        });
        block_on(async move { cb_receiver.await? })
    }
}
