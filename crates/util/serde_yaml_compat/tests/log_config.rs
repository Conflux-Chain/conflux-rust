// Copyright 2026 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use log4rs::config::{load_config_file, Deserializers, RawConfig};
use std::{fs, time::Duration};

#[test]
fn loads_repository_logging_config() {
    let directory = tempfile::tempdir().unwrap();
    let mut yaml: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../../run/log.yaml")).unwrap();
    yaml["appenders"]["logfile"]["path"] = serde_yaml::Value::String(
        directory
            .path()
            .join("conflux.log")
            .to_str()
            .unwrap()
            .into(),
    );
    yaml["appenders"]["logfile"]["policy"]["roller"]["pattern"] =
        serde_yaml::Value::String(
            directory
                .path()
                .join("archive/conflux.{}.gz")
                .to_str()
                .unwrap()
                .into(),
        );
    let source = serde_yaml::to_string(&yaml).unwrap();
    let raw: RawConfig = serde_yaml::from_str(&source).unwrap();
    assert_eq!(raw.refresh_rate(), Some(Duration::from_secs(30)));
    let (appenders, errors) = raw.appenders_lossy(&Deserializers::default());
    assert!(errors.is_empty(), "{errors}");
    assert_eq!(appenders.len(), 2);
    drop(appenders);

    let path = directory.path().join("log.yaml");
    fs::write(&path, source).unwrap();
    let config = load_config_file(&path, Deserializers::default()).unwrap();
    assert_eq!(config.appenders().len(), 2);
    assert_eq!(config.root().level().as_str(), "INFO");
    assert_eq!(config.root().appenders(), &["stdout", "logfile"]);
    assert!(config
        .loggers()
        .iter()
        .any(|logger| logger.name() == "cfx_storage"
            && logger.level().as_str() == "INFO"));
}

#[test]
fn rejects_invalid_logging_configuration() {
    for source in ["root: {level: invalid}", "unexpected_setting: true"] {
        assert!(serde_yaml::from_str::<RawConfig>(source).is_err());
    }
}
