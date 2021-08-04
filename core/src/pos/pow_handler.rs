use crate::{
    executive::internal_contract::impls::pos::decode_register_info,
    ConsensusGraph,
};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use cfx_parameters::internal_contract_addresses::POS_REGISTER_CONTRACT_ADDRESS;
use cfx_types::H256;
use futures::channel::oneshot;
use parking_lot::RwLock;
use pow_types::{PowInterface, StakingEvent};
use primitives::filter::{LogFilter, LogFilterParams};
use std::{sync::Arc, time::Duration};
use tokio::runtime::Handle;

// FIXME(lpl): Decide the value.
pub const POS_TERM_EPOCHS: u64 = 50;

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

    pub fn stop(&self) {
        let pow_consensus = &mut *self.pow_consensus.write();
        if pow_consensus.is_some() {
            info!(
                "Stop PowHandler: current consensus strong_count={}",
                Arc::strong_count(pow_consensus.as_ref().unwrap())
            );
            *pow_consensus = None;
        }
    }

    fn next_pivot_decision_impl(
        pow_consensus: Arc<ConsensusGraph>, parent_decision: &H256,
    ) -> Option<(u64, H256)> {
        let inner = pow_consensus.inner.read();
        let confirmed_height =
            pow_consensus.confirmation_meter.get_confirmed_epoch_num();
        inner.get_next_pivot_decision(parent_decision, confirmed_height)
    }

    fn validate_proposal_pivot_decision_impl(
        pow_consensus: Arc<ConsensusGraph>, parent_decision: &H256,
        me_decision: &H256,
    ) -> bool
    {
        pow_consensus
            .inner
            .read()
            .validate_pivot_decision(parent_decision, me_decision)
    }

    fn get_staking_events_impl(
        pow_consensus: Arc<ConsensusGraph>, parent_decision: H256,
        me_decision: H256,
    ) -> Result<Vec<StakingEvent>>
    {
        // We only call this for committed blocks, so it is guaranteed that
        // `parent_decision` is an ancestor of `me_decision`.
        if parent_decision == me_decision {
            return Ok(vec![]);
        }
        let start_epoch = pow_consensus
            .data_man
            .block_height_by_hash(&parent_decision)
            .ok_or(anyhow!("parent decision block missing"))?;
        let end_epoch = pow_consensus
            .data_man
            .block_height_by_hash(&me_decision)
            .ok_or(anyhow!("new decision block missing"))?;
        // start_epoch has been processed by parent.
        let from_epoch = (start_epoch + 1).into();
        let to_epoch = end_epoch.into();
        let mut params = LogFilterParams::default();
        params.address = Some(vec![*POS_REGISTER_CONTRACT_ADDRESS]);
        let log_filter = LogFilter::EpochLogFilter {
            from_epoch,
            to_epoch,
            params,
        };
        Ok(pow_consensus
            .logs(log_filter)
            .map_err(|e| anyhow!("Logs not available: e={}", e))?
            .into_iter()
            .map(|localized_entry| {
                decode_register_info(&localized_entry.entry)
                    .expect("address checked")
            })
            .collect())
    }
}

// FIXME(lpl): We should let the caller to decide if `pow_consensus` should be
// `None`?
#[async_trait]
impl PowInterface for PowHandler {
    async fn next_pivot_decision(
        &self, parent_decision: H256,
    ) -> Option<(u64, H256)> {
        let pow_consensus = self.pow_consensus.read().clone();
        if pow_consensus.is_none() {
            return None;
        }
        let (callback, cb_receiver) = oneshot::channel();
        let pow_consensus = pow_consensus.unwrap();
        self.executor.spawn(async move {
            let r =
                Self::next_pivot_decision_impl(pow_consensus, &parent_decision);
            assert!(callback.send(r).is_ok());
        });
        cb_receiver.await.expect("callback error")
    }

    fn validate_proposal_pivot_decision(
        &self, parent_decision: H256, me_decision: H256,
    ) -> bool {
        let pow_consensus = self.pow_consensus.read().clone();
        if pow_consensus.is_none() {
            return true;
        }
        let pow_consensus = pow_consensus.unwrap();
        debug!("before spawn pivot_decision");
        let r = Self::validate_proposal_pivot_decision_impl(
            pow_consensus,
            &parent_decision,
            &me_decision,
        );
        debug!("after spawn pivot_decision");
        r
    }

    /// Return error if pow_consensus has not been initialized or the pivot
    /// decision blocks have not been processed in PoW. Thus, a PoS node
    /// will not vote for new pivot decisions if the PoW block has not been
    /// processed.
    fn get_staking_events(
        &self, parent_decision: H256, me_decision: H256,
    ) -> Result<Vec<StakingEvent>> {
        let pow_consensus = self.pow_consensus.read().clone();
        if pow_consensus.is_none() {
            // This case will be reached during pos recovery.
            bail!("PoW consensus not initialized");
        }
        debug!(
            "get_staking_events: parent={:?}, me={:?}",
            parent_decision, me_decision
        );
        let pow_consensus = pow_consensus.unwrap();
        Self::get_staking_events_impl(
            pow_consensus,
            parent_decision,
            me_decision,
        )
    }

    async fn wait_for_initialization(&self, last_decision: H256) {
        while self.pow_consensus.read().is_none() {
            self.executor
                .block_on(tokio::time::sleep(Duration::from_millis(200)))
        }
        // TODO(lpl): Wait for last_decision is stable?
        // TODO(lpl): Delay events GC?
        while self
            .pow_consensus
            .read()
            .as_ref()
            .unwrap()
            .data_man
            .get_epoch_execution_commitment(&last_decision)
            .is_none()
        {
            self.executor
                .block_on(tokio::time::sleep(Duration::from_millis(200)))
        }
    }
}
