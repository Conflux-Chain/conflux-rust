use crate::ConsensusGraph;
use async_trait::async_trait;
use cfx_types::H256;
use diem_types::account_address::AccountAddress;
use futures::{channel::oneshot, executor::block_on};
use parking_lot::RwLock;
use pow_types::PowInterface;
use std::{collections::HashMap, sync::Arc};
use tokio::runtime::Handle;

pub const POS_TERM_EPOCHS: u64 = 60;
pub const POW_CONFIRM_DELAY_EPOCH: u64 = 60;

pub struct PowHandler {
    executor: Handle,
    pow_consensus: RwLock<Option<Arc<ConsensusGraph>>>,
}

impl PowHandler {
    pub fn new(executor: Handle) -> Self {
        Self {
            executor,
            pow_consensus: RwLock::new(None),
        }
    }

    pub fn initialize(&self, pow_consensus: Arc<ConsensusGraph>) {
        *self.pow_consensus.write() = Some(pow_consensus);
    }

    fn next_pivot_decision_impl(
        pow_consensus: Arc<ConsensusGraph>, parent_decision: &H256,
    ) -> Option<H256> {
        pow_consensus
            .inner
            .read()
            .get_next_pivot_decision(parent_decision)
    }

    fn validate_proposal_pivot_decision_impl(
        pow_consensus: Arc<ConsensusGraph>, parent_decision: &H256,
        me_decision: &H256,
    ) -> bool
    {
        pow_consensus
            .inner
            .read()
            .is_ancestor_of(parent_decision, me_decision)
    }

    fn get_committee_candidates_impl(
        _pow_consensus: Arc<ConsensusGraph>,
    ) -> HashMap<AccountAddress, u64> {
        todo!("Implement committee change later")
    }
}

// FIXME(lpl): We should let the caller to decide if `pow_consensus` should be
// `None`?
#[async_trait]
impl PowInterface for PowHandler {
    async fn next_pivot_decision(&self, parent_decision: H256) -> Option<H256> {
        let pow_consensus = self.pow_consensus.read().clone();
        if pow_consensus.is_none() {
            return None;
        }
        let (callback, cb_receiver) = oneshot::channel();
        let pow_consensus = pow_consensus.unwrap();
        self.executor.spawn(async move {
            let r =
                Self::next_pivot_decision_impl(pow_consensus, &parent_decision);
            callback.send(r);
        });
        cb_receiver.await.expect("callback error")
    }

    async fn validate_proposal_pivot_decision(
        &self, parent_decision: H256, me_decision: H256,
    ) -> bool {
        let pow_consensus = self.pow_consensus.read().clone();
        if pow_consensus.is_none() {
            return true;
        }
        let (callback, cb_receiver) = oneshot::channel();
        let pow_consensus = pow_consensus.unwrap();
        self.executor.spawn(async move {
            let r = Self::validate_proposal_pivot_decision_impl(
                pow_consensus,
                &parent_decision,
                &me_decision,
            );
            callback.send(r);
        });
        cb_receiver.await.expect("callback error")
    }

    async fn get_committee_candidates(&self) -> HashMap<AccountAddress, u64> {
        let pow_consensus = self.pow_consensus.read().clone();
        if pow_consensus.is_none() {
            return HashMap::new();
        }
        let (callback, cb_receiver) = oneshot::channel();
        let pow_consensus = pow_consensus.unwrap();
        self.executor.spawn(async move {
            let r = Self::get_committee_candidates_impl(pow_consensus);
            callback.send(r);
        });
        cb_receiver.await.expect("callback error")
    }
}
