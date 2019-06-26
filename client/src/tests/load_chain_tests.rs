// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate tempdir;

use self::tempdir::TempDir;
use super::super::{Client, Configuration};
use cfx_types::H256;
use parking_lot::{Condvar, Mutex};
use serde_json::Value;
use std::{
    fs::File,
    io::Read,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn get_expected_best_hash() -> String {
    let mut file =
        File::open(r#"../tests/blockchain_tests/general_2.json"#).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let json: Value = serde_json::from_str(data.as_str())
        .expect("JSON was not well-formatted");

    if let Value::Array(blocks) = json {
        for block_value in blocks.iter().rev() {
            if let Value::Object(ref block) = block_value {
                let epoch_value = &block["epochNumber"];
                if let Value::Null = epoch_value {
                    continue;
                }
                let hash_value = &block["hash"];
                if let Value::String(hash) = hash_value {
                    return hash.clone();
                }
            }
            panic!("JSON was not well-formatted");
        }
    }
    panic!("JSON was not well-formatted");
}

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
        Some(r#"../tests/blockchain_tests/general_2.json"#.to_owned());
    conf.raw_conf.port = Some(13000);
    conf.raw_conf.jsonrpc_http_port = Some(18000);

    let exit = Arc::new((Mutex::new(false), Condvar::new()));
    let handle = Client::start(conf, exit.clone()).unwrap();

    let expected = get_expected_best_hash();
    let best_block_hash: H256 =
        serde_json::from_str(&format!("{:?}", expected.as_str())).unwrap();
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
