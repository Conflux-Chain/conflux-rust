use crate::ConsensusGraph;
use cfx_types::H256;
use diem_types::account_address::AccountAddress;
use futures::{channel::oneshot, executor::block_on};
use std::{collections::HashMap, sync::Arc};
use tokio::runtime::Handle;
use async_trait::async_trait;
use pow_types::PowInterface;

pub const POS_TERM_EPOCHS: u64 = 60;


pub struct PowHandler {
    executor: Handle,
    pow_consensus: Arc<ConsensusGraph>,
}

impl PowHandler {
    pub fn new(executor: Handle, pow_consensus: Arc<ConsensusGraph>) -> Self {
        Self {
            executor,
            pow_consensus,
        }
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

#[async_trait]
impl PowInterface for PowHandler {
    async fn next_pivot_decision(
        &self, parent_decision: H256,
    ) -> Option<H256> {
        let (callback, cb_receiver) = oneshot::channel();
        let pow_consensus = self.pow_consensus.clone();
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
        let (callback, cb_receiver) = oneshot::channel();
        let pow_consensus = self.pow_consensus.clone();
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
        let (callback, cb_receiver) = oneshot::channel();
        let pow_consensus = self.pow_consensus.clone();
        self.executor.spawn(async move {
            let r = Self::get_committee_candidates_impl(pow_consensus);
            callback.send(r);
        });
        cb_receiver.await.expect("callback error")
    }
}
