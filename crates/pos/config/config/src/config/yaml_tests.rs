// Copyright 2026 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{NodeConfig, PersistableConfig};
use std::path::{Path, PathBuf};

#[test]
fn loads_and_round_trips_node_configuration() {
    let config = NodeConfig::parse(
        r#"
base:
  data_dir: node-data
consensus:
  round_initial_timeout_ms: 12345
logger:
  level: WARN
  file: node.log
storage:
  rocksdb_config:
    max_total_wal_size: 1099511627776
"#,
    )
    .unwrap();
    assert_eq!(config.data_dir(), Path::new("node-data"));
    assert_eq!(config.consensus.round_initial_timeout_ms, 12345);
    assert_eq!(config.logger.level, diem_logger::Level::Warn);
    assert_eq!(config.logger.file, Some(PathBuf::from("node.log")));
    assert_eq!(config.storage.rocksdb_config.max_total_wal_size, 1u64 << 40);

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pos_config.yaml");
    config.save_config(&path).unwrap();
    assert_eq!(NodeConfig::load(&path).unwrap(), config);
}

#[test]
fn rejects_unknown_fields_and_invalid_values() {
    for source in [
        "unexpected_setting: true",
        "consensus: {unexpected_setting: true}",
        "consensus: {round_initial_timeout_ms: -1}",
        "logger: {level: invalid}",
    ] {
        assert!(NodeConfig::parse(source).is_err(), "{}", source);
    }
}
