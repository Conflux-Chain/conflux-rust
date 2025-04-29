use super::{deserializer::deserialize_str_as_u64, SpecName};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlobConfig {
    #[serde(deserialize_with = "deserialize_str_as_u64")]
    pub target: u64,
    #[serde(deserialize_with = "deserialize_str_as_u64")]
    pub max: u64,
    #[serde(deserialize_with = "deserialize_str_as_u64")]
    pub base_fee_update_fraction: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub blob_schedule: Option<HashMap<SpecName, BlobConfig>>,
    #[serde(deserialize_with = "deserialize_str_as_u64")]
    pub chainid: u64,
    pub network: Option<SpecName>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize() {
        let json = r#"
        {
            "blobSchedule": {
                "Cancun": {
                    "target": "0x03",
                    "max": "0x06",
                    "baseFeeUpdateFraction": "0x32f0ed"
                }
            },
            "chainid": "0x01"
        }
        "#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.chainid, 1);
        assert!(config.blob_schedule.is_some());

        let json = r#"
        {
            "chainid": "0x01"
        }
        "#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert!(!config.blob_schedule.is_some());
    }
}
