// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    genesis_block::GenesisPosState,
    pos::{
        consensus::{
            consensus_provider::start_consensus,
            gen_consensus_reconfig_subscription,
            network::NetworkReceivers as ConsensusNetworkReceivers,
            ConsensusDB, TestCommand,
        },
        mempool as diem_mempool,
        mempool::{
            gen_mempool_reconfig_subscription,
            network::NetworkReceivers as MemPoolNetworkReceivers,
            SubmissionStatus,
        },
        pow_handler::PowHandler,
        protocol::{
            network_sender::NetworkSender,
            sync_protocol::HotStuffSynchronizationProtocol,
        },
        state_sync::bootstrapper::StateSyncBootstrapper,
    },
    sync::ProtocolConfiguration,
};

use cached_pos_ledger_db::CachedPosLedgerDB;
use consensus_types::db::FakeLedgerBlockDB;
use diem_config::{config::NodeConfig, utils::get_genesis_txn};
use diem_logger::{prelude::*, Writer};
use diem_types::{
    account_address::{from_consensus_public_key, AccountAddress},
    block_info::PivotBlockDecision,
    term_state::NodeID,
    transaction::SignedTransaction,
    validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey},
    PeerId,
};
use executor::{db_bootstrapper::maybe_bootstrap, vm::PosVM, Executor};
use executor_types::ChunkExecutor;
use futures::{
    channel::{
        mpsc::{self, channel},
        oneshot,
    },
    executor::block_on,
};
use network::NetworkService;
use pos_ledger_db::PosLedgerDB;
use pow_types::FakePowHandler;
use std::{
    boxed::Box,
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
use storage_interface::DbReaderWriter;
use tokio::runtime::Runtime;

const AC_SMP_CHANNEL_BUFFER_SIZE: usize = 1_024;
const INTRA_NODE_CHANNEL_BUFFER_SIZE: usize = 1;

pub struct PosDropHandle {
    // pow handler
    pub pow_handler: Arc<PowHandler>,
    pub pos_ledger_db: Arc<PosLedgerDB>,
    pub cached_db: Arc<CachedPosLedgerDB>,
    pub consensus_db: Arc<ConsensusDB>,
    pub tx_sender: mpsc::Sender<(
        SignedTransaction,
        oneshot::Sender<anyhow::Result<SubmissionStatus>>,
    )>,
    pub stopped: Arc<AtomicBool>,
    _mempool: Runtime,
    _state_sync_bootstrapper: StateSyncBootstrapper,
    _consensus_runtime: Runtime,
}

pub fn start_pos_consensus(
    config: &NodeConfig, network: Arc<NetworkService>,
    protocol_config: ProtocolConfiguration,
    own_pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
    pos_genesis_state: GenesisPosState,
    consensus_network_receiver: ConsensusNetworkReceivers,
    mempool_network_receiver: MemPoolNetworkReceivers,
    test_command_receiver: channel::Receiver<TestCommand>,
    hsb_protocol: Arc<HotStuffSynchronizationProtocol>,
) -> PosDropHandle {
    crash_handler::setup_panic_handler();

    let mut logger = diem_logger::Logger::new();
    logger
        .channel_size(config.logger.chan_size)
        .is_async(config.logger.is_async)
        .level(config.logger.level)
        .read_env();
    if let Some(log_file) = config.logger.file.clone() {
        if let Some(parent) = log_file.parent() {
            fs::create_dir_all(parent).expect(&format!(
                "error creating PoS log file directory: parent={:?}",
                parent
            ));
        }
        let writer = match config.logger.rotation_count {
            Some(count) => Box::new(RollingFileWriter::new(
                log_file,
                count,
                config.logger.rotation_file_size_mb.unwrap_or(500),
            ))
                as Box<dyn Writer + Send + Sync + 'static>,
            None => Box::new(FileWriter::new(log_file))
                as Box<dyn Writer + Send + Sync + 'static>,
        };
        logger.printer(writer);
    }
    let _logger = Some(logger.build());

    // Let's now log some important information, since the logger is set up
    diem_info!(config = config, "Loaded Pos config");

    /*if config.metrics.enabled {
        for network in &config.full_node_networks {
            let peer_id = network.peer_id();
            setup_metrics(peer_id, &config);
        }

        if let Some(network) = config.validator_network.as_ref() {
            let peer_id = network.peer_id();
            setup_metrics(peer_id, &config);
        }
    }*/
    if fail::has_failpoints() {
        diem_warn!("Failpoints is enabled");
        if let Some(failpoints) = &config.failpoints {
            for (point, actions) in failpoints {
                fail::cfg(point, actions)
                    .expect("fail to set actions for failpoint");
            }
        }
    } else if config.failpoints.is_some() {
        diem_warn!("failpoints is set in config, but the binary doesn't compile with this feature");
    }

    setup_pos_environment(
        &config,
        network,
        protocol_config,
        own_pos_public_key,
        pos_genesis_state,
        consensus_network_receiver,
        mempool_network_receiver,
        test_command_receiver,
        hsb_protocol,
    )
}

#[allow(unused)]
fn setup_metrics(peer_id: PeerId, config: &NodeConfig) {
    diem_metrics::dump_all_metrics_to_file_periodically(
        &config.metrics.dir(),
        &format!("{}.metrics", peer_id),
        config.metrics.collection_interval_ms,
    );
}

fn setup_chunk_executor(db: DbReaderWriter) -> Box<dyn ChunkExecutor> {
    Box::new(Executor::<PosVM>::new(
        Arc::new(CachedPosLedgerDB::new(db)),
        Arc::new(FakePowHandler {}),
        Arc::new(FakeLedgerBlockDB {}),
    ))
}

pub fn setup_pos_environment(
    node_config: &NodeConfig, network: Arc<NetworkService>,
    protocol_config: ProtocolConfiguration,
    own_pos_public_key: Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
    pos_genesis_state: GenesisPosState,
    consensus_network_receiver: ConsensusNetworkReceivers,
    mempool_network_receiver: MemPoolNetworkReceivers,
    test_command_receiver: channel::Receiver<TestCommand>,
    hsb_protocol: Arc<HotStuffSynchronizationProtocol>,
) -> PosDropHandle {
    // TODO(lpl): Handle port conflict.
    // let metrics_port = node_config.debug_interface.metrics_server_port;
    // let metric_host = node_config.debug_interface.address.clone();
    // thread::spawn(move || {
    //     metric_server::start_server(metric_host, metrics_port, false)
    // });
    // let public_metrics_port =
    //     node_config.debug_interface.public_metrics_server_port;
    // let public_metric_host = node_config.debug_interface.address.clone();
    // thread::spawn(move || {
    //     metric_server::start_server(
    //         public_metric_host,
    //         public_metrics_port,
    //         true,
    //     )
    // });

    let mut instant = Instant::now();
    let (pos_ledger_db, db_rw) = DbReaderWriter::wrap(
        PosLedgerDB::open(
            &node_config.storage.dir(),
            false, /* readonly */
            node_config.storage.prune_window,
            node_config.storage.rocksdb_config,
        )
        .expect("DB should open."),
    );

    let genesis_waypoint = node_config.base.waypoint.genesis_waypoint();
    // if there's genesis txn and waypoint, commit it if the result matches.
    if let Some(genesis) = get_genesis_txn(&node_config) {
        maybe_bootstrap::<PosVM>(
            &db_rw,
            genesis,
            genesis_waypoint,
            Some(PivotBlockDecision {
                block_hash: protocol_config.pos_genesis_pivot_decision,
                height: 0,
            }),
            pos_genesis_state.initial_seed.as_bytes().to_vec(),
            pos_genesis_state
                .initial_nodes
                .into_iter()
                .map(|node| {
                    (NodeID::new(node.bls_key, node.vrf_key), node.voting_power)
                })
                .collect(),
            pos_genesis_state.initial_committee,
        )
        .expect("Db-bootstrapper should not fail.");
    } else {
        panic!("Genesis txn not provided.");
    }

    debug!(
        "Storage service started in {} ms",
        instant.elapsed().as_millis()
    );

    instant = Instant::now();
    let chunk_executor = setup_chunk_executor(db_rw.clone());
    debug!(
        "ChunkExecutor setup in {} ms",
        instant.elapsed().as_millis()
    );
    let mut reconfig_subscriptions = vec![];

    let (mempool_reconfig_subscription, mempool_reconfig_events) =
        gen_mempool_reconfig_subscription();
    reconfig_subscriptions.push(mempool_reconfig_subscription);
    // consensus has to subscribe to ALL on-chain configs
    let (consensus_reconfig_subscription, consensus_reconfig_events) =
        gen_consensus_reconfig_subscription();
    if node_config.base.role.is_validator() {
        reconfig_subscriptions.push(consensus_reconfig_subscription);
    }

    // for state sync to send requests to mempool
    let (state_sync_to_mempool_sender, state_sync_requests) =
        channel(INTRA_NODE_CHANNEL_BUFFER_SIZE);
    let state_sync_bootstrapper = StateSyncBootstrapper::bootstrap(
        state_sync_to_mempool_sender,
        Arc::clone(&db_rw.reader),
        chunk_executor,
        node_config,
        genesis_waypoint,
        reconfig_subscriptions,
    );

    let state_sync_client = state_sync_bootstrapper
        .create_client(node_config.state_sync.client_commit_timeout_ms);

    let (consensus_to_mempool_sender, consensus_requests) =
        channel(INTRA_NODE_CHANNEL_BUFFER_SIZE);

    let network_sender = NetworkSender {
        network,
        protocol_handler: hsb_protocol,
    };

    let (mp_client_sender, mp_client_events) =
        channel(AC_SMP_CHANNEL_BUFFER_SIZE);

    let db_with_cache = Arc::new(CachedPosLedgerDB::new(db_rw));

    instant = Instant::now();
    let mempool = diem_mempool::bootstrap(
        node_config,
        db_with_cache.clone(),
        network_sender.clone(),
        mempool_network_receiver,
        mp_client_events,
        consensus_requests,
        state_sync_requests,
        mempool_reconfig_events,
    );
    debug!("Mempool started in {} ms", instant.elapsed().as_millis());

    // Make sure that state synchronizer is caught up at least to its waypoint
    // (in case it's present). There is no sense to start consensus prior to
    // that. TODO: Note that we need the networking layer to be able to
    // discover & connect to the peers with potentially outdated network
    // identity public keys.
    debug!("Wait until state sync is initialized");
    block_on(state_sync_client.wait_until_initialized())
        .expect("State sync initialization failure");
    debug!("State sync initialization complete.");

    // Initialize and start consensus.
    instant = Instant::now();
    debug!("own_pos_public_key: {:?}", own_pos_public_key);
    let (consensus_runtime, pow_handler, stopped, consensus_db) =
        start_consensus(
            node_config,
            network_sender,
            consensus_network_receiver,
            consensus_to_mempool_sender,
            state_sync_client,
            pos_ledger_db.clone(),
            db_with_cache.clone(),
            consensus_reconfig_events,
            own_pos_public_key.map_or_else(
                || AccountAddress::random(),
                |public_key| {
                    from_consensus_public_key(&public_key.0, &public_key.1)
                },
            ),
            mp_client_sender.clone(),
            test_command_receiver,
            protocol_config.pos_started_as_voter,
        );
    debug!("Consensus started in {} ms", instant.elapsed().as_millis());

    PosDropHandle {
        pow_handler,
        _consensus_runtime: consensus_runtime,
        stopped,
        _state_sync_bootstrapper: state_sync_bootstrapper,
        _mempool: mempool,
        pos_ledger_db,
        cached_db: db_with_cache,
        consensus_db,
        tx_sender: mp_client_sender,
    }
}

impl Drop for PosDropHandle {
    fn drop(&mut self) {
        debug!("Drop PosDropHandle");
        self.stopped.store(true, Ordering::SeqCst);
        self.pow_handler.stop();
    }
}
