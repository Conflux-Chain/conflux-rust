// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use cfx_types::H256;
use cfxcore::{
    pos::{
        consensus::{
            consensus_provider::start_consensus,
            gen_consensus_reconfig_subscription,
        },
        pow_handler::PowHandler,
    },
    sync::ProtocolConfiguration,
};
use diem_config::{config::NodeConfig, utils::get_genesis_txn};
use diem_crypto::ed25519::Ed25519PublicKey;
use diem_logger::prelude::*;
use diem_metrics::metric_server;
use diem_types::{
    account_address::{from_public_key, AccountAddress},
    PeerId,
};
use diemdb::DiemDB;
use executor::{db_bootstrapper::maybe_bootstrap, vm::FakeVM, Executor};
use executor_types::ChunkExecutor;
use futures::executor::block_on;
use network::NetworkService;
use state_sync::bootstrapper::StateSyncBootstrapper;
use std::{boxed::Box, path::PathBuf, sync::Arc, thread, time::Instant};
use storage_interface::DbReaderWriter;
use tokio::runtime::Runtime;

pub struct DiemHandle {
    // pow handler
    pub pow_handler: Arc<PowHandler>,
    pub diem_db: Arc<DiemDB>,
    _state_sync_bootstrapper: StateSyncBootstrapper,
    _consensus_runtime: Runtime,
}

pub fn start_pos_consensus(
    config: &NodeConfig, log_file: Option<PathBuf>,
    network: Arc<NetworkService>, own_node_hash: H256,
    protocol_config: ProtocolConfiguration,
    own_pos_public_key: Option<Ed25519PublicKey>,
) -> DiemHandle
{
    crash_handler::setup_panic_handler();

    let mut logger = diem_logger::Logger::new();
    logger
        .channel_size(config.logger.chan_size)
        .is_async(config.logger.is_async)
        .level(config.logger.level)
        .read_env();
    if let Some(log_file) = log_file {
        logger.printer(Box::new(FileWriter::new(log_file)));
    }
    let _logger = Some(logger.build());

    // Let's now log some important information, since the logger is set up
    diem_info!(config = config, "Loaded DiemNode config");

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
        own_node_hash,
        protocol_config,
        own_pos_public_key,
    )
}

fn setup_metrics(peer_id: PeerId, config: &NodeConfig) {
    diem_metrics::dump_all_metrics_to_file_periodically(
        &config.metrics.dir(),
        &format!("{}.metrics", peer_id),
        config.metrics.collection_interval_ms,
    );
}

fn setup_chunk_executor(db: DbReaderWriter) -> Box<dyn ChunkExecutor> {
    Box::new(Executor::<FakeVM>::new(db))
}

pub fn setup_pos_environment(
    node_config: &NodeConfig, network: Arc<NetworkService>,
    own_node_hash: H256, protocol_config: ProtocolConfiguration,
    own_pos_public_key: Option<Ed25519PublicKey>,
) -> DiemHandle
{
    let metrics_port = node_config.debug_interface.metrics_server_port;
    let metric_host = node_config.debug_interface.address.clone();
    thread::spawn(move || {
        metric_server::start_server(metric_host, metrics_port, false)
    });
    let public_metrics_port =
        node_config.debug_interface.public_metrics_server_port;
    let public_metric_host = node_config.debug_interface.address.clone();
    thread::spawn(move || {
        metric_server::start_server(
            public_metric_host,
            public_metrics_port,
            true,
        )
    });

    let mut instant = Instant::now();
    let (diem_db, db_rw) = DbReaderWriter::wrap(
        DiemDB::open(
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
        maybe_bootstrap::<FakeVM>(&db_rw, genesis, genesis_waypoint)
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

    // consensus has to subscribe to ALL on-chain configs
    let (consensus_reconfig_subscription, consensus_reconfig_events) =
        gen_consensus_reconfig_subscription();
    if node_config.base.role.is_validator() {
        reconfig_subscriptions.push(consensus_reconfig_subscription);
    }

    let state_sync_bootstrapper = StateSyncBootstrapper::bootstrap(
        //state_sync_network_handles,
        Arc::clone(&db_rw.reader),
        chunk_executor,
        node_config,
        genesis_waypoint,
        reconfig_subscriptions,
    );

    let state_sync_client = state_sync_bootstrapper
        .create_client(node_config.state_sync.client_commit_timeout_ms);

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
    let (consensus_runtime, pow_handler) = start_consensus(
        node_config,
        network,
        own_node_hash,
        protocol_config,
        state_sync_client,
        diem_db.clone(),
        db_rw,
        consensus_reconfig_events,
        own_pos_public_key.map_or_else(
            || AccountAddress::random(),
            |public_key| from_public_key(&public_key),
        ),
    );
    debug!("Consensus started in {} ms", instant.elapsed().as_millis());

    DiemHandle {
        pow_handler,
        _consensus_runtime: consensus_runtime,
        _state_sync_bootstrapper: state_sync_bootstrapper,
        diem_db,
    }
}
