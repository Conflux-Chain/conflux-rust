// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate tempdir;

use self::tempdir::TempDir;
use super::super::{Client, Configuration};
use cfx_types::H256;
use parking_lot::{Condvar, Mutex};
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[test]
fn test_load_chain() {
    let mut conf = Configuration::default();
    conf.raw_conf.test_mode = true;
    let tmp_dir = TempDir::new("conflux-test").unwrap();
    conf.raw_conf.db_dir = Some(
        tmp_dir
            .path()
            .join("db")
            .into_os_string()
            .into_string()
            .unwrap(),
    );
    conf.raw_conf.netconf_dir = Some(
        tmp_dir
            .path()
            .join("config")
            .into_os_string()
            .into_string()
            .unwrap(),
    );
    conf.raw_conf.load_test_chain =
        Some(r#"../test/blockchain_tests/general_2.json"#.to_owned());
    conf.raw_conf.port = Some(13000);
    conf.raw_conf.jsonrpc_http_port = Some(18000);

    let exit = Arc::new((Mutex::new(false), Condvar::new()));
    let handle = Client::start(conf, exit.clone()).unwrap();

    let expected =
        "0xe561d06c4a89d6b28553be9be59b21a1a306721b93100fe413395da7b63683e0";
    let best_block_hash: H256 =
        serde_json::from_str(&format!("{:?}", expected)).unwrap();
    let max_timeout = Duration::from_secs(60);

    let instant = Instant::now();
    let sleep_duration = Duration::from_secs(1);

    while instant.elapsed() < max_timeout {
        if handle
            .consensus
            .get_block_epoch_number(&best_block_hash)
            .is_some()
        {
            break;
        }
        thread::sleep(sleep_duration);
    }

    assert_eq!(best_block_hash, handle.consensus.best_block_hash());

    Client::close(handle);
}
