/// The parameters needed to determine the chain_id based on epoch_number.
#[derive(Clone, Debug, Eq, RlpEncodable, RlpDecodable, PartialEq, Default)]
pub struct ChainIdParamsDeprecated {
    /// Preconfigured chain_id.
    pub chain_id: u32,
}

impl ChainIdParamsDeprecated {
    /// The function return the chain_id with given parameters
    pub fn get_chain_id(&self, _epoch_number: u64) -> u32 {
        self.chain_id
    }
}

#[derive(Clone, Debug, Default, PartialEq, RlpEncodable, RlpDecodable)]
pub struct ChainIdParamsInner {
    heights: Vec<u64>,
    chain_ids: Vec<u32>,
}

pub type ChainIdParams = Arc<RwLock<ChainIdParamsInner>>;

impl ChainIdParamsInner {
    /// The function return the chain_id with given parameters
    pub fn get_chain_id(&self, epoch_number: u64) -> u32 {
        let index = self
            .heights
            .binary_search(&epoch_number)
            .unwrap_or_else(|x| x - 1);
        self.chain_ids[index]
    }

    pub fn new_inner(chain_id: u32) -> Self {
        Self {
            heights: vec![0],
            chain_ids: vec![chain_id],
        }
    }

    pub fn new_simple(chain_id: u32) -> ChainIdParams {
        Arc::new(RwLock::new(Self::new_inner(chain_id)))
    }

    pub fn new_from_inner(x: &Self) -> ChainIdParams {
        Arc::new(RwLock::new(x.clone()))
    }

    pub fn parse_config_str(config: &str) -> std::result::Result<Self, String> {
        let mut parsed = Self::default();
        let value = config
            .parse::<toml::Value>()
            .map_err(|e| format!("{}", e))?;
        if let toml::Value::Table(table) = &value {
            if let Some(height_to_chain_ids) = table.get("height_to_chain_ids")
            {
                if let toml::Value::Array(array) = height_to_chain_ids {
                    if array.len() == 0 {
                        return Err(String::from("Invalid ChainIdParams config format: height_to_chain_ids is empty"));
                    }
                    let mut used_chain_ids = BTreeSet::new();
                    for element in array {
                        if let toml::Value::Array(pair) = element {
                            if pair.len() != 2 {
                                return Err(String::from("Invalid ChainIdParams config format: height_to_chain_ids elements is not [height, chain_id]"));
                            }
                            if let [toml::Value::Integer(height), toml::Value::Integer(chain_id)] =
                                &pair[0..2]
                            {
                                if *height < 0 {
                                    return Err(String::from("Invalid ChainIdParams config format: height must be positive"));
                                }
                                if used_chain_ids.contains(chain_id) {
                                    return Err(String::from("Invalid ChainIdParams config format: chain_id must be pairwise different"));
                                }
                                if *chain_id < 0
                                    || *chain_id > std::u32::MAX as i64
                                {
                                    return Err(String::from("Invalid ChainIdParams config format: chain_id out of range for u32"));
                                }
                                parsed.heights.push(*height as u64);
                                parsed.chain_ids.push(*chain_id as u32);
                                used_chain_ids.insert(*chain_id);
                            }
                        } else {
                            return Err(String::from("Invalid ChainIdParams config format: height_to_chain_ids elements is not [height, chain_id]"));
                        }
                    }
                } else {
                    return Err(String::from("Invalid ChainIdParams config format: height_to_chain_ids is not an array"));
                }
            } else {
                return Err(String::from("Invalid ChainIdParams config format: height_to_chain_ids not found"));
            }
            if parsed.heights[0] != 0 {
                return Err(String::from("Invalid ChainIdParams config format: height must start from 0"));
            }
            Ok(parsed)
        } else {
            return Err(String::from(
                "Invalid ChainIdParams config format: not a table",
            ));
        }
    }

    pub fn matches(&self, other: &Self, peer_epoch_number: u64) -> bool {
        // Sub-array check. One height to epoch id map must be a sub-array of
        // another.
        let min_len = min(self.heights.len(), other.heights.len());
        let sub_array_check = other.heights[0..min_len]
            == self.heights[0..min_len]
            && other.chain_ids[0..min_len] == self.chain_ids[0..min_len];

        if sub_array_check {
            // Check if peer has a high epoch_number but a shorter height to
            // epoch id map, so that the chain_id of ourselves is
            // not a match anymore.
            let index = self
                .heights
                .binary_search(&peer_epoch_number)
                .unwrap_or_else(|x| x - 1);
            min_len > index
        } else {
            return false;
        }
    }
}

impl From<ChainIdParamsDeprecated> for ChainIdParamsInner {
    fn from(x: ChainIdParamsDeprecated) -> Self {
        Self {
            heights: vec![0],
            chain_ids: vec![x.chain_id],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_config_str() {
        let config_str =
            "height_to_chain_ids = [[0, 0], [10000, 1], [20000, 2], [30000, 3]]";
        let config = ChainIdParamsInner::parse_config_str(config_str).unwrap();
        assert_eq!(
            config,
            ChainIdParamsInner {
                heights: vec![0, 10000, 20000, 30000],
                chain_ids: vec![0, 1, 2, 3],
            }
        );

        // Config can't be empty.
        let config_str = "";
        let config = ChainIdParamsInner::parse_config_str(config_str);
        assert!(config.is_err());

        // Height must start from 0.
        let config_str = "height_to_chain_ids = [[10, 1024]]";
        let config = ChainIdParamsInner::parse_config_str(config_str);
        assert!(config.is_err());

        // Must be array of array.
        let config_str = "height_to_chain_ids = [0, 1024]";
        let config = ChainIdParamsInner::parse_config_str(config_str);
        assert!(config.is_err());

        // Can not reuse chain_id.
        let config_str = "height_to_chain_ids = [[0, 0], [10000, 1], [20000, 2], [30000, 1]]";
        let config = ChainIdParamsInner::parse_config_str(config_str);
        assert!(config.is_err());

        let config_str = "height_to_chain_ids = [[0, 1024]]";
        let config = ChainIdParamsInner::parse_config_str(config_str).unwrap();
        assert_eq!(
            config,
            ChainIdParamsInner {
                heights: vec![0],
                chain_ids: vec![1024],
            }
        );
    }

    #[test]
    fn test_chain_id_at_height() {
        let config_str =
            "height_to_chain_ids = [[0, 0], [10000, 1], [20000, 2], [30000, 3]]";
        let config = ChainIdParamsInner::parse_config_str(config_str).unwrap();
        assert_eq!(config.get_chain_id(0), 0);
        assert_eq!(config.get_chain_id(1), 0);
        assert_eq!(config.get_chain_id(9999), 0);
        assert_eq!(config.get_chain_id(10000), 1);
        assert_eq!(config.get_chain_id(10001), 1);
        assert_eq!(config.get_chain_id(19999), 1);
        assert_eq!(config.get_chain_id(20000), 2);
        assert_eq!(config.get_chain_id(20001), 2);
        assert_eq!(config.get_chain_id(29999), 2);
        assert_eq!(config.get_chain_id(30000), 3);
        assert_eq!(config.get_chain_id(30001), 3);
    }

    #[test]
    fn test_chain_id_peer_compatibility() {
        let epoch_number = 30000;
        let config = ChainIdParamsInner::parse_config_str(
            "height_to_chain_ids = [[0, 0], [10000, 1], [20000, 2], [30000, 3]]",
        )
        .unwrap();
        let compatible_config_1 = ChainIdParamsInner::parse_config_str(
            "height_to_chain_ids = [[0, 0], [10000, 1], [20000, 2]]",
        )
        .unwrap();
        let compatible_config_2 = ChainIdParamsInner::parse_config_str(
            "height_to_chain_ids = [[0, 0], [10000, 1], [20000, 2], [30000, 3], [40000, 4], [50000, 5]]",
        )
            .unwrap();
        let incompatible_config_1 = ChainIdParamsInner::parse_config_str(
            "height_to_chain_ids = [[0, 0], [10000, 1], [20000, 2], [30000, 4]]",
        )
            .unwrap();
        let incompatible_config_2 = ChainIdParamsInner::parse_config_str(
            "height_to_chain_ids = [[0, 0], [10000, 1], [20000, 2], [25000, 3]]",
        )
            .unwrap();
        let incompatible_config_3 = ChainIdParamsInner::parse_config_str(
            "height_to_chain_ids = [[0, 0], [10000, 1]]",
        )
        .unwrap();

        assert!(config.matches(&compatible_config_1, epoch_number - 1));
        assert!(!config.matches(&compatible_config_1, epoch_number));
        assert!(config.matches(&compatible_config_2, epoch_number));
        assert!(!config.matches(&incompatible_config_1, epoch_number));
        assert!(!config.matches(&incompatible_config_1, epoch_number - 1));
        assert!(!config.matches(&incompatible_config_2, epoch_number));
        assert!(!config.matches(&incompatible_config_3, epoch_number));
    }
}

use parking_lot::RwLock;
use std::{cmp::min, collections::BTreeSet, sync::Arc};
