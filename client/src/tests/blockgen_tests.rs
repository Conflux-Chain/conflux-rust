// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate tempdir;

use self::tempdir::TempDir;
use crate::{
    archive::{ArchiveClient, ArchiveClientExtraComponents},
    common::{client_methods, ClientComponents},
    configuration::Configuration,
};
use blockgen::BlockGenerator;
use parking_lot::{Condvar, Mutex};
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn test_mining_10_epochs_inner(
    handle: &ClientComponents<BlockGenerator, ArchiveClientExtraComponents>,
) {
    let bgen = handle.blockgen.clone().unwrap();
    //println!("Pow Config: {:?}", bgen.pow_config());
    thread::spawn(move || {
        BlockGenerator::start_mining(bgen, 0);
    });
    let sync_graph = handle.other_components.sync.get_synchronization_graph();
    let best_block_hash = sync_graph.consensus.best_block_hash();
    let start_height =
        sync_graph.block_height_by_hash(&best_block_hash).unwrap();

    let sleep_duration = Duration::from_secs(1);
    let max_timeout = Duration::from_secs(60);

    let instant = Instant::now();
    while instant.elapsed() < max_timeout {
        let new_best_block_hash = sync_graph.consensus.best_block_hash();
        let end_height = sync_graph
            .block_height_by_hash(&new_best_block_hash)
            .unwrap();
        info!("{}", end_height - start_height);
        if end_height - start_height >= 10 {
            handle.blockgen.as_ref().unwrap().stop();
            return;
        }
        thread::sleep(sleep_duration);
    }
    let new_best_block_hash = sync_graph.consensus.best_block_hash();
    let end_height = sync_graph
        .block_height_by_hash(&new_best_block_hash)
        .unwrap();
    handle.blockgen.as_ref().unwrap().stop();
    panic!(
        "Mined too few blocks, delta height is only {}.",
        end_height - start_height
    );
}

#[test]
fn test_mining_10_epochs() {
    let mut conf = Configuration::default();
    conf.raw_conf.mode = Some("test".to_owned());
    conf.raw_conf.initial_difficulty = Some(10_000);

    let tmp_dir = TempDir::new("conflux-test").unwrap();
    conf.raw_conf.conflux_data_dir =
        tmp_dir.path().to_str().unwrap().to_string() + "/";
    conf.raw_conf.block_db_dir = tmp_dir
        .path()
        .join("db")
        .into_os_string()
        .into_string()
        .unwrap();
    conf.raw_conf.netconf_dir = Some(
        tmp_dir
            .path()
            .join("config")
            .into_os_string()
            .into_string()
            .unwrap(),
    );
    conf.raw_conf.port = Some(13001);
    conf.raw_conf.jsonrpc_http_port = Some(18001);
    conf.raw_conf.mining_author =
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());

    let exit = Arc::new((Mutex::new(false), Condvar::new()));
    let handle = ArchiveClient::start(conf, exit).unwrap();

    test_mining_10_epochs_inner(&handle);

    client_methods::shutdown(handle);
}
