// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{pos::consensus::ConsensusDB, ConsensusGraph};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use cfx_executor::internal_contract::decode_register_info;
use cfx_parameters::internal_contract_addresses::POS_REGISTER_CONTRACT_ADDRESS;
use cfx_types::H256;
use diem_types::block_info::PivotBlockDecision;
use futures::channel::oneshot;
use parking_lot::RwLock;
use pow_types::{PowInterface, StakingEvent};
use primitives::filter::{LogFilter, LogFilterParams};
use std::{
    sync::{atomic::Ordering, Arc, Weak},
    time::Duration,
};
use tokio::runtime::Handle;

// TODO(lpl): Decide the value.
pub const POS_TERM_EPOCHS: u64 = 60;

pub struct PowHandler {
    executor: Handle,
    pow_consensus: RwLock<Option<Weak<ConsensusGraph>>>,
    pos_consensus_db: Arc<ConsensusDB>,
}

impl PowHandler {
    pub fn new(executor: Handle, pos_consensus_db: Arc<ConsensusDB>) -> Self {
        Self {
            executor,
            pow_consensus: RwLock::new(None),
            pos_consensus_db,
        }
    }

    pub fn initialize(&self, pow_consensus: Arc<ConsensusGraph>) {
        *self.pow_consensus.write() = Some(Arc::downgrade(&pow_consensus));
    }

    pub fn stop(&self) {
        let pow_consensus = &mut *self.pow_consensus.write();
        if pow_consensus.is_some() {
            debug!(
                "Consensus ref count:{}",
                Weak::strong_count(pow_consensus.as_ref().unwrap())
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
    ) -> bool {
        pow_consensus
            .inner
            .read()
            .validate_pivot_decision(parent_decision, me_decision)
    }

    fn get_staking_events_impl(
        pow_consensus: Arc<ConsensusGraph>, parent_decision: H256,
        me_decision: H256,
    ) -> Result<Vec<StakingEvent>> {
        // We only call this for committed blocks, so it is guaranteed that
        // `parent_decision` is an ancestor of `me_decision`.
        if parent_decision == me_decision {
            return Ok(vec![]);
        }
        let start_epoch = pow_consensus
            .data_man
            .block_height_by_hash(&parent_decision)
            .ok_or(anyhow!(
                "parent decision block missing, hash={:?}",
                parent_decision
            ))?;
        let end_epoch = pow_consensus
            .data_man
            .block_height_by_hash(&me_decision)
            .ok_or(anyhow!(
                "new decision block missing, hash={:?}",
                me_decision
            ))?;
        // start_epoch has been processed by parent.
        let from_epoch = (start_epoch + 1).into();
        let to_epoch = end_epoch.into();
        let mut params = LogFilterParams::default();
        params.address = Some(vec![POS_REGISTER_CONTRACT_ADDRESS]);
        params.trusted = true;
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

// TODO(lpl): We should let the caller to decide if `pow_consensus` should be
// `None`?
#[async_trait]
impl PowInterface for PowHandler {
    async fn next_pivot_decision(
        &self, parent_decision: H256,
    ) -> Option<(u64, H256)> {
        let pow_consensus =
            self.pow_consensus.read().clone().and_then(|c| c.upgrade());
        if pow_consensus.is_none() {
            return None;
        }
        let (callback, cb_receiver) = oneshot::channel();
        let pow_consensus = pow_consensus.unwrap();
        self.executor.spawn(async move {
            let r =
                Self::next_pivot_decision_impl(pow_consensus, &parent_decision);
            if let Err(e) = callback.send(r) {
                debug!("send next_pivot_decision err={:?}", e);
            }
        });
        cb_receiver.await.ok().flatten()
    }

    fn validate_proposal_pivot_decision(
        &self, parent_decision: H256, me_decision: H256,
    ) -> bool {
        let pow_consensus =
            self.pow_consensus.read().clone().and_then(|c| c.upgrade());
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
        &self, parent_height: u64, me_height: u64, parent_decision: H256,
        me_decision: H256,
    ) -> Result<Vec<StakingEvent>> {
        let pow_consensus =
            self.pow_consensus.read().clone().and_then(|c| c.upgrade());
        if pow_consensus.is_none() {
            // This case will be reached during pos recovery.
            bail!("PoW consensus not initialized");
        }
        debug!(
            "get_staking_events: parent={:?}, me={:?}",
            parent_decision, me_decision
        );
        let pow_consensus = pow_consensus.unwrap();
        if parent_decision == pow_consensus.data_man.true_genesis.hash() {
            // `me_decision` is the first actual pow_decision. It may be far
            // from genesis, so getting all event can be slow or
            // even unavailable. We just drop all events before this
            // first pow_decision. And in normal cases, these events
            // have been processed to produce the PoS genesis, so they should
            // not be packed again.
            return Ok(vec![]);
        }
        self.pos_consensus_db
            .get_staking_events(
                PivotBlockDecision {
                    height: parent_height,
                    block_hash: parent_decision,
                },
                PivotBlockDecision {
                    height: me_height,
                    block_hash: me_decision,
                },
            )
            .or_else(|e| {
                debug!("get_staking_events from pow: err={:?}", e);
                Self::get_staking_events_impl(
                    pow_consensus,
                    parent_decision,
                    me_decision,
                )
            })
    }

    async fn wait_for_initialization(&self, last_decision: H256) {
        debug!("wait_for_initialization: {:?}", last_decision);
        while self.pow_consensus.read().is_none() {
            tokio::time::sleep(Duration::from_millis(200)).await
        }
        // TODO(lpl): Wait for last_decision is stable?
        loop {
            // Check epoch hash set to see if last_decision is processed and is
            // on the pivot chain. Note that for full nodes, there
            // is no other persisted data to check for old blocks.
            {
                if self
                    .pow_consensus
                    .read()
                    .as_ref()
                    .unwrap()
                    .upgrade()
                    .unwrap()
                    .inner
                    .read()
                    .pivot_block_processed(&last_decision)
                {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await
        }
    }

    fn is_normal_phase(&self) -> bool {
        self.pow_consensus
            .read()
            .as_ref()
            .and_then(|p| {
                p.upgrade().map(|consensus| {
                    consensus.ready_for_mining.load(Ordering::SeqCst)
                })
            })
            .unwrap_or(false)
    }
}
