// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::error::Error;
use diem_types::{
    epoch_change::Verifier, epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
};
use executor_types::ExecutedTrees;

/// SyncState contains the following fields:
/// * `committed_ledger_info` holds the latest certified ledger info (committed
///   to storage), i.e., the ledger info for the highest version for which
///   storage has all ledger state.
/// * `synced_trees` holds the latest transaction accumulator and state tree
///   (which may or may not be committed to storage), i.e., some ledger state
///   for the next highest ledger info version is missing.
/// * `trusted_epoch_state` corresponds to the current epoch if the highest
///   committed ledger info (`committed_ledger_info`) is in the middle of the
///   epoch, otherwise, it corresponds to the next epoch if the highest
///   committed ledger info ends the epoch.
///
/// Note: `committed_ledger_info` is used for helping other Diem nodes
/// synchronize (i.e., it corresponds to the highest version we have a proof for
/// in storage). `synced_trees` is used locally for retrieving missing chunks
/// for the local storage.
#[derive(Clone, Debug)]
pub struct SyncState {
    committed_ledger_info: LedgerInfoWithSignatures,
    synced_trees: ExecutedTrees,
    trusted_epoch_state: EpochState,
}

impl SyncState {
    pub fn new(
        committed_ledger_info: LedgerInfoWithSignatures,
        synced_trees: ExecutedTrees, current_epoch_state: EpochState,
    ) -> Self
    {
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

    /// Returns the highest available version in the local storage, even if it's
    /// not committed (i.e., covered by a ledger info).
    pub fn synced_version(&self) -> u64 {
        self.synced_trees.version().unwrap_or(0)
    }

    pub fn trusted_epoch(&self) -> u64 { self.trusted_epoch_state.epoch }

    pub fn verify_ledger_info(
        &self, ledger_info: &LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        self.trusted_epoch_state
            .verify(ledger_info)
            .map_err(|error| Error::UnexpectedError(error.to_string()))
    }
}

/*
#[cfg(any(feature = "fuzzing", test))]
pub(crate) mod test_utils {
    use crate::{
        coordinator::StateSyncCoordinator,
        executor_proxy::{ExecutorProxy, ExecutorProxyTrait},
        network::StateSyncSender,
    };
    use diem_types::waypoint::Waypoint;

    use channel::{diem_channel, message_queues::QueueStyle};
    use diem_config::{
        config::{NodeConfig, RoleType},
        network_id::{NetworkId, NodeNetworkId},
    };
    use diem_types::transaction::{Transaction, WriteSetPayload};
    use diem_vm::DiemVM;
    use diemdb::DiemDB;
    use executor::Executor;
    use executor_test_helpers::bootstrap_genesis;
    use futures::channel::mpsc;
    use network::{
        peer_manager::{ConnectionRequestSender, PeerManagerRequestSender},
        protocols::network::NewNetworkSender,
    };
    use std::collections::HashMap;
    use storage_interface::DbReaderWriter;

    #[cfg(test)]
    pub(crate) fn create_coordinator_with_config_and_waypoint(
        node_config: NodeConfig, waypoint: Waypoint,
    ) -> StateSyncCoordinator<ExecutorProxy> {
        create_state_sync_coordinator_for_tests(node_config, waypoint)
    }

    pub(crate) fn create_validator_coordinator(
    ) -> StateSyncCoordinator<ExecutorProxy> {
        let mut node_config = NodeConfig::default();
        node_config.base.role = RoleType::Validator;

        create_state_sync_coordinator_for_tests(
            node_config,
            Waypoint::default(),
        )
    }

    #[cfg(test)]
    pub(crate) fn create_full_node_coordinator(
    ) -> StateSyncCoordinator<ExecutorProxy> {
        let mut node_config = NodeConfig::default();
        node_config.base.role = RoleType::FullNode;

        create_state_sync_coordinator_for_tests(
            node_config,
            Waypoint::default(),
        )
    }

    fn create_state_sync_coordinator_for_tests(
        node_config: NodeConfig, waypoint: Waypoint,
    ) -> StateSyncCoordinator<ExecutorProxy> {
        // Generate a genesis change set
        let (genesis, _) =
            vm_genesis::test_genesis_change_set_and_validators(Some(1));

        // Create test diem database
        let db_path = diem_temppath::TempPath::new();
        db_path.create_as_dir().unwrap();
        let (db, db_rw) =
            DbReaderWriter::wrap(DiemDB::new_for_test(db_path.path()));

        // Bootstrap the genesis transaction
        let genesis_txn =
            Transaction::GenesisTransaction(WriteSetPayload::Direct(genesis));
        bootstrap_genesis::<DiemVM>(&db_rw, &genesis_txn).unwrap();

        // Create executor proxy
        let chunk_executor = Box::new(Executor::<DiemVM>::new(db_rw));
        let executor_proxy = ExecutorProxy::new(db, chunk_executor, vec![]);

        // Get initial state
        let initial_state = executor_proxy.get_local_storage_state().unwrap();

        // Setup network senders
        let (network_reqs_tx, _network_reqs_rx) =
            diem_channel::new(QueueStyle::FIFO, 8, None);
        let (connection_reqs_tx, _) =
            diem_channel::new(QueueStyle::FIFO, 8, None);
        let network_sender = StateSyncSender::new(
            PeerManagerRequestSender::new(network_reqs_tx),
            ConnectionRequestSender::new(connection_reqs_tx),
        );
        let node_network_id = NodeNetworkId::new(NetworkId::Validator, 0);
        let network_senders = vec![(node_network_id, network_sender)]
            .into_iter()
            .collect::<HashMap<_, _>>();

        // Create channel senders and receivers
        let (_coordinator_sender, coordinator_receiver) = mpsc::unbounded();
        let (mempool_sender, _mempool_receiver) = mpsc::channel(1);

        // Return the new state sync coordinator
        StateSyncCoordinator::new(
            coordinator_receiver,
            mempool_sender,
            network_senders,
            &node_config,
            waypoint,
            executor_proxy,
            initial_state,
        )
        .unwrap()
    }
}
*/
