// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate tempdir;

use self::tempdir::TempDir;
use crate::{
    archive::ArchiveClient, common::client_methods,
    configuration::Configuration, rpc::RpcBlock,
};
use cfx_types::H256;
use cfxcore::ConsensusGraphTrait;
use parking_lot::{Condvar, Mutex};
use primitives::Block;
use serde_json::Value;
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
use serial_test::serial;

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
#[serial] // TODO: remove
fn test_load_chain() {
    let mut conf = Configuration::default();
    conf.raw_conf.mode = Some("test".to_owned());
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
    conf.raw_conf.tcp_port = 13000;
    conf.raw_conf.jsonrpc_http_port = Some(18000);
    conf.raw_conf.chain_id = Some(10);
    conf.raw_conf.execute_genesis = false;

    let exit = Arc::new((Mutex::new(false), Condvar::new()));
    let handle = ArchiveClient::start(conf, exit).unwrap();

    let chain_path = "../tests/blockchain_tests/general_2.json";

    // make sure db recovery has completed
    thread::sleep(Duration::from_secs(7));

    let file_path = Path::new(&chain_path);
    let file = File::open(file_path)
        .map_err(|e| format!("Failed to open test-chain file {:?}", e))
        .ok()
        .unwrap();
    let reader = BufReader::new(file);
    let rpc_blocks: Vec<RpcBlock> = serde_json::from_reader(reader)
        .map_err(|e| format!("Failed to parse blocks from json {:?}", e))
        .ok()
        .unwrap();
    assert!(
        !rpc_blocks.is_empty(),
        "Error: The json data should not be empty."
    );
    for rpc_block in rpc_blocks.into_iter().skip(1) {
        let primitive_block: Block = rpc_block.into_primitive().map_err(|e| {
            format!("Failed to convert from a rpc_block to primitive block {:?}", e)
        }).ok().unwrap();
        handle
            .other_components
            .sync
            .on_mined_block(primitive_block)
            .ok();
    }

    let expected = get_expected_best_hash();
    let best_block_hash: H256 =
        serde_json::from_str(&format!("{:?}", expected.as_str())).unwrap();
    let max_timeout = Duration::from_secs(60);

    let instant = Instant::now();
    let sleep_duration = Duration::from_secs(1);

    while instant.elapsed() < max_timeout {
        if handle
            .other_components
            .consensus
            .get_block_epoch_number(&best_block_hash)
            .is_some()
        {
            break;
        }
        thread::sleep(sleep_duration);
    }

    assert_eq!(
        best_block_hash,
        handle.other_components.consensus.best_block_hash()
    );

    client_methods::shutdown(handle);
}
