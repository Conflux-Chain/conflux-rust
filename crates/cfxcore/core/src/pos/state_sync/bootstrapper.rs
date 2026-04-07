// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
use crate::pos::{
    mempool as diem_mempool,
    state_sync::{
        client::{CoordinatorMessage, StateSyncClient},
        coordinator::StateSyncCoordinator,
        executor_proxy::{ExecutorProxy, ExecutorProxyTrait},
    },
};
use diem_config::config::NodeConfig;
use futures::channel::mpsc;
use std::sync::Arc;
use storage_interface::DbReader;
use subscription_service::ReconfigSubscription;
use tokio::runtime::{Builder, Runtime};

/// Creates and bootstraps new state syncs and creates clients for
/// communicating with those state syncs.
pub struct StateSyncBootstrapper {
    _runtime: Runtime,
    coordinator_sender: mpsc::UnboundedSender<CoordinatorMessage>,
}

impl StateSyncBootstrapper {
    pub fn bootstrap(
        state_sync_to_mempool_sender: mpsc::Sender<
            diem_mempool::CommitNotification,
        >,
        storage: Arc<dyn DbReader>, node_config: &NodeConfig,
        reconfig_event_subscriptions: Vec<ReconfigSubscription>,
    ) -> Self {
        let runtime = Builder::new_multi_thread()
            .thread_name("state-sync")
            .enable_all()
            .build()
            .expect("[State Sync] Failed to create runtime!");

        let executor_proxy =
            ExecutorProxy::new(storage, reconfig_event_subscriptions);
        Self::bootstrap_with_executor_proxy(
            runtime,
            state_sync_to_mempool_sender,
            node_config,
            executor_proxy,
        )
    }

    pub fn bootstrap_with_executor_proxy<E: ExecutorProxyTrait + 'static>(
        runtime: Runtime,
        state_sync_to_mempool_sender: mpsc::Sender<
            diem_mempool::CommitNotification,
        >,
        node_config: &NodeConfig, executor_proxy: E,
    ) -> Self {
        let (coordinator_sender, coordinator_receiver) = mpsc::unbounded();
        let initial_state = executor_proxy
            .get_local_storage_state()
            .expect("[State Sync] Starting failure: cannot sync with storage!");

        let coordinator = StateSyncCoordinator::new(
            coordinator_receiver,
            state_sync_to_mempool_sender,
            node_config,
            executor_proxy,
            initial_state,
        )
        .expect("[State Sync] Unable to create state sync coordinator!");
        runtime.spawn(coordinator.start());

        Self {
            _runtime: runtime,
            coordinator_sender,
        }
    }

    pub fn create_client(&self, commit_timeout_secs: u64) -> StateSyncClient {
        StateSyncClient::new(
            self.coordinator_sender.clone(),
            commit_timeout_secs,
        )
    }
}
