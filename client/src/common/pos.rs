// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use cfx_types::H256;
use cfxcore::{
    pos::consensus::{
        consensus_provider::start_consensus,
        gen_consensus_reconfig_subscription,
    },
    sync::ProtocolConfiguration,
};
use diem_config::{config::NodeConfig, utils::get_genesis_txn};
use diem_logger::prelude::*;
use diem_metrics::metric_server;
use diem_types::PeerId;
use diemdb::DiemDB;
use executor::{db_bootstrapper::maybe_bootstrap, vm::FakeVM, Executor};
use executor_types::BlockExecutor;
use network::NetworkService;
use std::{boxed::Box, sync::Arc, thread, time::Instant};
use storage_interface::DbReaderWriter;
use tokio::runtime::Runtime;

pub fn start_pos_consensus(
    config: &NodeConfig, network: Arc<NetworkService>, own_node_hash: H256,
    protocol_config: ProtocolConfiguration,
) -> Runtime
{
    crash_handler::setup_panic_handler();

    // Let's now log some important information, since the logger is set up
    diem_info!(config = config, "Loaded DiemNode config");

    if config.metrics.enabled {
        for network in &config.full_node_networks {
            let peer_id = network.peer_id();
            setup_metrics(peer_id, &config);
        }

        if let Some(network) = config.validator_network.as_ref() {
            let peer_id = network.peer_id();
            setup_metrics(peer_id, &config);
        }
    }
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

    setup_pos_environment(&config, network, own_node_hash, protocol_config)
}

fn setup_metrics(peer_id: PeerId, config: &NodeConfig) {
    diem_metrics::dump_all_metrics_to_file_periodically(
        &config.metrics.dir(),
        &format!("{}.metrics", peer_id),
        config.metrics.collection_interval_ms,
    );
}

fn setup_chunk_executor(db: DbReaderWriter) -> Box<dyn BlockExecutor> {
    Box::new(Executor::<FakeVM>::new(db))
}

pub fn setup_pos_environment(
    node_config: &NodeConfig, network: Arc<NetworkService>,
    own_node_hash: H256, protocol_config: ProtocolConfiguration,
) -> Runtime
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
        info!("Genesis txn not provided, it's fine if you don't expect to apply it otherwise please double check config");
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

    // Initialize and start consensus.
    instant = Instant::now();
    let consensus_runtime = start_consensus(
        node_config,
        network,
        own_node_hash,
        protocol_config,
        diem_db,
        chunk_executor,
        consensus_reconfig_events,
    );
    debug!("Consensus started in {} ms", instant.elapsed().as_millis());

    consensus_runtime
}
