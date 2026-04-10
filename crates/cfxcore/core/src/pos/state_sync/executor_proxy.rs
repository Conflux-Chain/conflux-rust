// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::state_sync::logging::{LogEntry, LogEvent, LogSchema};
use diem_logger::prelude::*;
use diem_types::{
    contract_event::ContractEvent,
    ledger_info::LedgerInfoWithSignatures,
    on_chain_config::{OnChainConfigPayload, ON_CHAIN_CONFIG_REGISTRY},
};
use executor_types::ExecutedTrees;
use itertools::Itertools;
use std::{collections::HashSet, sync::Arc};
use storage_interface::DbReader;
use subscription_service::ReconfigSubscription;

/// The local sync state maintained by the coordinator.
#[derive(Clone, Debug)]
pub struct SyncState {
    committed_ledger_info: LedgerInfoWithSignatures,
    synced_trees: ExecutedTrees,
    trusted_epoch_state: diem_types::epoch_state::EpochState,
}

impl SyncState {
    pub fn new(
        committed_ledger_info: LedgerInfoWithSignatures,
        synced_trees: ExecutedTrees,
        current_epoch_state: diem_types::epoch_state::EpochState,
    ) -> Self {
        let trusted_epoch_state = committed_ledger_info
            .ledger_info()
            .next_epoch_state()
            .cloned()
            .unwrap_or(current_epoch_state);

        SyncState {
            committed_ledger_info,
            synced_trees,
            trusted_epoch_state,
        }
    }

    pub fn committed_epoch(&self) -> u64 {
        self.committed_ledger_info.ledger_info().epoch()
    }

    pub fn committed_ledger_info(&self) -> LedgerInfoWithSignatures {
        self.committed_ledger_info.clone()
    }

    pub fn committed_version(&self) -> u64 {
        self.committed_ledger_info.ledger_info().version()
    }

    pub fn synced_version(&self) -> u64 {
        self.synced_trees.version().unwrap_or(0)
    }

    pub fn trusted_epoch(&self) -> u64 { self.trusted_epoch_state.epoch }
}

/// Proxies interactions with execution and storage for state synchronization
pub trait ExecutorProxyTrait: Send {
    /// Sync the local state with the latest in storage.
    fn get_local_storage_state(&self) -> Result<SyncState, anyhow::Error>;

    /// Get the epoch changing ledger info for the given epoch so that we can
    /// move to next epoch.
    fn get_epoch_change_ledger_info(
        &self, epoch: u64,
    ) -> Result<LedgerInfoWithSignatures, anyhow::Error>;

    /// Returns the ledger's timestamp for the given version in microseconds
    fn get_version_timestamp(&self, version: u64)
        -> Result<u64, anyhow::Error>;

    /// publishes on-chain config updates to subscribed components
    fn publish_on_chain_config_updates(
        &mut self, events: Vec<ContractEvent>,
    ) -> Result<(), anyhow::Error>;
}

pub(crate) struct ExecutorProxy {
    storage: Arc<dyn DbReader>,
    reconfig_subscriptions: Vec<ReconfigSubscription>,
    on_chain_configs: OnChainConfigPayload,
}

impl ExecutorProxy {
    pub(crate) fn new(
        storage: Arc<dyn DbReader>,
        mut reconfig_subscriptions: Vec<ReconfigSubscription>,
    ) -> Self {
        let on_chain_configs =
            if let Ok(Some(startup_info)) = storage.get_startup_info(false) {
                let epoch_state = startup_info
                    .latest_epoch_state
                    .or(startup_info
                        .latest_ledger_info
                        .ledger_info()
                        .next_epoch_state()
                        .cloned())
                    .expect("[state sync] EpochState must exist after genesis");
                OnChainConfigPayload::new(
                    epoch_state.epoch,
                    Arc::new(
                        ON_CHAIN_CONFIG_REGISTRY
                            .iter()
                            .cloned()
                            .zip_eq(vec![bcs::to_bytes(&epoch_state).unwrap()])
                            .collect(),
                    ),
                )
            } else {
                // Pre-bootstrap: no startup info yet, use default config
                OnChainConfigPayload::new(
                    0,
                    Arc::new(
                        ON_CHAIN_CONFIG_REGISTRY
                            .iter()
                            .cloned()
                            .zip_eq(vec![vec![]])
                            .collect(),
                    ),
                )
            };

        for subscription in reconfig_subscriptions.iter_mut() {
            subscription.publish(on_chain_configs.clone()).expect(
                "[state sync] Failed to publish initial on-chain config",
            );
        }
        Self {
            storage,
            reconfig_subscriptions,
            on_chain_configs,
        }
    }
}

impl ExecutorProxyTrait for ExecutorProxy {
    fn get_local_storage_state(&self) -> Result<SyncState, anyhow::Error> {
        let storage_info =
            self.storage.get_startup_info(false).map_err(|error| {
                anyhow::anyhow!(
                    "Failed to get startup info from storage: {}",
                    error
                )
            })?;
        let storage_info = storage_info.ok_or_else(|| {
            anyhow::anyhow!("Missing startup info from storage")
        })?;
        let current_epoch_state = storage_info.get_epoch_state().clone();

        let synced_trees =
            if let Some(synced_tree_state) = storage_info.synced_tree_state {
                ExecutedTrees::from(synced_tree_state)
            } else {
                ExecutedTrees::new_with_pos_state(
                    storage_info.committed_tree_state,
                    storage_info.committed_pos_state,
                )
            };

        Ok(SyncState::new(
            storage_info.latest_ledger_info,
            synced_trees,
            current_epoch_state,
        ))
    }

    fn get_epoch_change_ledger_info(
        &self, epoch: u64,
    ) -> Result<LedgerInfoWithSignatures, anyhow::Error> {
        let next_epoch = epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Next epoch has overflown!"))?;
        let mut epoch_ending_ledger_infos = self
            .storage
            .get_epoch_ending_ledger_infos(epoch, next_epoch)
            .map_err(|error| anyhow::anyhow!("{}", error))?;

        epoch_ending_ledger_infos
            .ledger_info_with_sigs
            .pop()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Missing epoch change ledger info for epoch: {:?}",
                    epoch
                )
            })
    }

    fn get_version_timestamp(
        &self, version: u64,
    ) -> Result<u64, anyhow::Error> {
        self.storage
            .get_block_timestamp(version)
            .map_err(|error| anyhow::anyhow!("{}", error))
    }

    fn publish_on_chain_config_updates(
        &mut self, events: Vec<ContractEvent>,
    ) -> Result<(), anyhow::Error> {
        if events.is_empty() {
            return Ok(());
        }
        diem_info!(LogSchema::new(LogEntry::Reconfig)
            .count(events.len())
            .reconfig_events(events.clone()));

        let event_keys = events
            .iter()
            .map(|event| *event.key())
            .collect::<HashSet<_>>();

        // calculate deltas
        let new_configs = OnChainConfigPayload::new(
            1, /* not used */
            Arc::new(
                ON_CHAIN_CONFIG_REGISTRY
                    .iter()
                    .cloned()
                    .zip_eq(vec![events[0].event_data().to_vec()])
                    .collect(),
            ),
        );
        diem_debug!("get {} configs", new_configs.configs().len());

        let changed_configs = new_configs
            .configs()
            .iter()
            .filter(|(id, cfg)| {
                &self.on_chain_configs.configs().get(id).unwrap_or_else(|| {
                    panic!(
                        "Missing on-chain config value in local copy: {}",
                        id
                    )
                }) != cfg
            })
            .map(|(id, _)| *id)
            .collect::<HashSet<_>>();

        // notify subscribers
        let mut publish_success = true;
        for subscription in self.reconfig_subscriptions.iter_mut() {
            let subscribed_items = subscription.subscribed_items();
            if !changed_configs.is_disjoint(&subscribed_items.configs)
                || !event_keys.is_disjoint(&subscribed_items.events)
            {
                diem_debug!("publish {} configs", new_configs.configs().len());
                if let Err(e) = subscription.publish(new_configs.clone()) {
                    publish_success = false;
                    diem_error!(
                        LogSchema::event_log(
                            LogEntry::Reconfig,
                            LogEvent::PublishError
                        )
                        .subscription_name(subscription.name.clone()),
                        "Failed to publish reconfig notification to subscription {}: {}",
                        subscription.name,
                        e
                    );
                } else {
                    diem_info!(
                        LogSchema::event_log(
                            LogEntry::Reconfig,
                            LogEvent::Success
                        )
                        .subscription_name(subscription.name.clone()),
                        "Successfully published reconfig notification to subscription {}",
                        subscription.name
                    );
                }
            }
        }

        self.on_chain_configs = new_configs;
        if publish_success {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to publish at least one subscription!"
            ))
        }
    }
}
