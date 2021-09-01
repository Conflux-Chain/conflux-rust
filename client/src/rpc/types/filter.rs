// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{EpochNumber, RpcAddress};
use crate::rpc::helpers::{maybe_vec_into, VariadicValue};
use cfx_types::{H256, U64};
use jsonrpc_core::Error as RpcError;
use primitives::filter::{LogFilter as PrimitiveFilter, LogFilterParams};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const FILTER_BLOCK_HASH_LIMIT: usize = 128;

#[derive(PartialEq, Debug, Serialize, Deserialize, Eq, Hash, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogFilter {
    /// Search will be applied from this epoch number.
    pub from_epoch: Option<EpochNumber>,

    /// Till this epoch number.
    pub to_epoch: Option<EpochNumber>,

    /// Search will be applied from this block number.
    pub from_block: Option<U64>,

    /// Till this block number.
    pub to_block: Option<U64>,

    /// Search will be applied in these blocks if given.
    /// This will override from/to_epoch fields.
    pub block_hashes: Option<Vec<H256>>,

    /// Search addresses.
    ///
    /// If None, match all.
    /// If specified, log must be produced by one of these addresses.
    pub address: Option<VariadicValue<RpcAddress>>,

    /// Search topics.
    ///
    /// Logs can have 4 topics: the function signature and up to 3 indexed
    /// event arguments. The elements of `topics` match the corresponding
    /// log topics. Example: ["0xA", null, ["0xB", "0xC"], null] matches
    /// logs with "0xA" as the 1st topic AND ("0xB" OR "0xC") as the 3rd
    /// topic. If None, match all.
    pub topics: Option<Vec<VariadicValue<H256>>>,

    /// Logs offset
    ///
    /// If None, return all logs
    /// If specified, should skip the *last* `n` logs.
    pub offset: Option<U64>,

    /// Logs limit
    ///
    /// If None, return all logs
    /// If specified, should only return *last* `n` logs
    /// after the offset has been applied.
    pub limit: Option<U64>,
}

impl LogFilter {
    pub fn into_primitive(self) -> Result<PrimitiveFilter, RpcError> {
        // from_epoch, to_epoch
        let from_epoch = self
            .from_epoch
            .clone()
            .unwrap_or(EpochNumber::LatestCheckpoint)
            .into();

        let to_epoch = self
            .to_epoch
            .clone()
            .unwrap_or(EpochNumber::LatestState)
            .into();

        // from_block, to_block
        let from_block = self.from_block.map(|x| x.as_u64());
        let to_block = self.to_block.map(|x| x.as_u64());

        // block_hashes
        match self.block_hashes {
            Some(ref bhs) if bhs.len() > FILTER_BLOCK_HASH_LIMIT => return Err(RpcError::invalid_params(
                format!("filter.block_hashes can contain up to {} hashes; {} were provided.", FILTER_BLOCK_HASH_LIMIT, bhs.len())
            )),
            _ => {}
        }

        let block_hashes = maybe_vec_into(&self.block_hashes);

        // topics
        match self.topics {
            Some(ref ts) if ts.len() > 4 => {
                return Err(RpcError::invalid_params(format!(
                    "filter.topics can contain up to 4 topics; {} were provided.",
                    ts.len()
                )))
            }
            _ => {}
        }

        let topics = {
            let mut iter = self
                .topics
                .map_or_else(Vec::new, |topics| {
                    topics.into_iter().take(4).map(Into::into).collect()
                })
                .into_iter();

            vec![
                iter.next().unwrap_or(None),
                iter.next().unwrap_or(None),
                iter.next().unwrap_or(None),
                iter.next().unwrap_or(None),
            ]
        };

        // address, limit
        let address = match self.address {
            None => None,
            Some(VariadicValue::Null) => None,
            Some(VariadicValue::Single(x)) => Some(vec![x.into()]),
            Some(VariadicValue::Multiple(xs)) => {
                Some(xs.into_iter().map(|x| x.into()).collect())
            }
        };

        let offset = self.offset.map(|x| x.as_u64() as usize);
        let limit = self.limit.map(|x| x.as_u64() as usize);

        let params = LogFilterParams {
            address,
            topics,
            offset,
            limit,
        };

        // choose filter type based on fields
        match (
            &self.from_epoch,
            &self.to_epoch,
            &self.from_block,
            &self.to_block,
            &self.block_hashes,
        ) {
            // block hash filter
            (None, None, None, None, Some(_)) => {
                let hashes = {
                    let mut hash_set = HashSet::new();
                    block_hashes
                        .unwrap()
                        .into_iter()
                        .filter(|&p| hash_set.insert(p))
                        .collect::<Vec<_>>()
                };
                Ok(PrimitiveFilter::BlockHashLogFilter {
                    block_hashes: hashes,
                    params,
                })
            }

            // block number range filter
            // (both from and to need to be provided)
            (None, None, Some(_), Some(_), None) => {
                Ok(PrimitiveFilter::BlockNumberLogFilter {
                    from_block: from_block.unwrap(),
                    to_block: to_block.unwrap(),
                    params,
                })
            }

            // epoch number range filter
            // (can be ommitted)
            (_, _, None, None, None) => Ok(PrimitiveFilter::EpochLogFilter {
                from_epoch,
                to_epoch,
                params,
            }),

            // any other case is considered an error
            _ => {
                bail!(RpcError::invalid_params(
                    format!("Filter must provide one of the following: (1) an epoch range through `fromEpoch` and `toEpoch`, (2) a block number range through `fromBlock` and `toBlock`, (3) a set of block hashes through `blockHashes`")
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::RpcAddress, EpochNumber, LogFilter, VariadicValue};
    use cfx_addr::Network;
    use cfx_types::{H160, H256, U64};
    use primitives::{
        epoch::EpochNumber as PrimitiveEpochNumber,
        filter::{LogFilter as PrimitiveFilter, LogFilterParams},
    };
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn test_serialize_filter() {
        let filter = LogFilter {
            from_epoch: None,
            to_epoch: None,
            from_block: None,
            to_block: None,
            block_hashes: None,
            address: None,
            topics: None,
            offset: None,
            limit: None,
        };

        let serialized_filter = serde_json::to_string(&filter).unwrap();

        assert_eq!(
            serialized_filter,
            "{\
             \"fromEpoch\":null,\
             \"toEpoch\":null,\
             \"fromBlock\":null,\
             \"toBlock\":null,\
             \"blockHashes\":null,\
             \"address\":null,\
             \"topics\":null,\
             \"offset\":null,\
             \"limit\":null\
             }"
        );

        let filter = LogFilter {
            from_epoch: Some(1000.into()),
            to_epoch: Some(EpochNumber::LatestState),
            from_block: Some(1000.into()),
            to_block: Some(1000.into()),
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000000").unwrap(), Network::Main).unwrap(),
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000001").unwrap(), Network::Main).unwrap(),
            ])),
            topics: Some(vec![
                VariadicValue::Single(H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()),
                VariadicValue::Multiple(vec![
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                ]),
            ]),
            offset: Some(U64::from(1)),
            limit: Some(U64::from(2)),
        };

        let serialized_filter = serde_json::to_string(&filter).unwrap();

        assert_eq!(
            serialized_filter,
            "{\
             \"fromEpoch\":\"0x3e8\",\
             \"toEpoch\":\"latest_state\",\
             \"fromBlock\":\"0x3e8\",\
             \"toBlock\":\"0x3e8\",\
             \"blockHashes\":[\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"],\
             \"address\":[\"CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2\",\"CFX:TYPE.BUILTIN:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEJC4EYEY6\"],\
             \"topics\":[\
                \"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\",\
                [\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\",\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\"]\
             ],\
             \"offset\":\"0x1\",\
             \"limit\":\"0x2\"\
             }"
        );
    }

    #[test]
    fn test_deserialize_filter() {
        let serialized = "{}";

        let result_filter = LogFilter {
            from_epoch: None,
            to_epoch: None,
            from_block: None,
            to_block: None,
            block_hashes: None,
            address: None,
            topics: None,
            offset: None,
            limit: None,
        };

        let deserialized_filter: LogFilter =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_filter, result_filter);

        let serialized = "{\
             \"fromEpoch\":\"0x3e8\",\
             \"toEpoch\":\"latest_state\",\
             \"fromBlock\":\"0x3e8\",\
             \"toBlock\":\"0x3e8\",\
             \"blockHashes\":[\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"],\
             \"address\":[\"CFX:TYPE.NULL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0SFBNJM2\",\"CFX:TYPE.BUILTIN:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEJC4EYEY6\"],\
             \"topics\":[\
                \"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\",\
                [\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\",\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\"]\
             ],\
             \"offset\":\"0x1\",\
             \"limit\":\"0x2\"\
        }";

        let result_filter = LogFilter {
            from_epoch: Some(1000.into()),
            to_epoch: Some(EpochNumber::LatestState),
            from_block: Some(1000.into()),
            to_block: Some(1000.into()),
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000000").unwrap(), Network::Main).unwrap(),
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000001").unwrap(), Network::Main).unwrap(),
            ])),
            topics: Some(vec![
                VariadicValue::Single(H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()),
                VariadicValue::Multiple(vec![
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                ]),
            ]),
            offset: Some(U64::from(1)),
            limit: Some(U64::from(2)),
        };

        let deserialized_filter: LogFilter =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_filter, result_filter);
    }

    #[test]
    fn test_convert_filter() {
        let epoch_filter = LogFilter {
            from_epoch: Some(EpochNumber::Earliest),
            to_epoch: None,
            from_block: None,
            to_block: None,
            block_hashes: None,
            address: Some(VariadicValue::Multiple(vec![
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000000").unwrap(), Network::Main).unwrap(),
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000001").unwrap(), Network::Main).unwrap(),
            ])),
            topics: Some(vec![
                VariadicValue::Single(H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()),
                VariadicValue::Multiple(vec![
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                ]),
            ]),
            offset: Some(U64::from(1)),
            limit: Some(U64::from(2)),
        };

        let primitive_epoch_filter = PrimitiveFilter::EpochLogFilter {
            from_epoch: PrimitiveEpochNumber::Earliest,
            to_epoch: PrimitiveEpochNumber::LatestState,
            params: LogFilterParams {
                address: Some(vec![
                    H160::from_str("0000000000000000000000000000000000000000").unwrap(),
                    H160::from_str("0000000000000000000000000000000000000001").unwrap(),
                ]),
                topics: vec![
                    Some(vec![H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()]),
                    Some(vec![
                        H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                        H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    ]),
                    None,
                    None,
                ],
                offset: Some(1),
                limit: Some(2),
            },
        };

        assert_eq!(epoch_filter.into_primitive(), Ok(primitive_epoch_filter));

        // -------------------------------------

        let block_number_filter = LogFilter {
            from_epoch: None,
            to_epoch: None,
            from_block: Some(U64::from(1)),
            to_block: Some(U64::from(2)),
            block_hashes: None,
            address: Some(VariadicValue::Multiple(vec![
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000000").unwrap(), Network::Main).unwrap(),
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000001").unwrap(), Network::Main).unwrap(),
            ])),
            topics: Some(vec![
                VariadicValue::Single(H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()),
                VariadicValue::Multiple(vec![
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                ]),
            ]),
            offset: Some(U64::from(1)),
            limit: Some(U64::from(2)),
        };

        let primitive_block_number_filter = PrimitiveFilter::BlockNumberLogFilter {
            from_block: 1,
            to_block: 2,
            params: LogFilterParams {
                address: Some(vec![
                    H160::from_str("0000000000000000000000000000000000000000").unwrap(),
                    H160::from_str("0000000000000000000000000000000000000001").unwrap(),
                ]),
                topics: vec![
                    Some(vec![H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()]),
                    Some(vec![
                        H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                        H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    ]),
                    None,
                    None,
                ],
                offset: Some(1),
                limit: Some(2),
            },
        };

        assert_eq!(
            block_number_filter.into_primitive(),
            Ok(primitive_block_number_filter)
        );

        // -------------------------------------

        let block_hash_filter = LogFilter {
            from_epoch: None,
            to_epoch: None,
            from_block: None,
            to_block: None,
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000000").unwrap(), Network::Main).unwrap(),
                RpcAddress::try_from_h160(H160::from_str("0000000000000000000000000000000000000001").unwrap(), Network::Main).unwrap(),
            ])),
            topics: Some(vec![
                VariadicValue::Single(H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()),
                VariadicValue::Multiple(vec![
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                ]),
            ]),
            offset: Some(U64::from(1)),
            limit: Some(U64::from(2)),
        };

        let primitive_block_hash_filter = PrimitiveFilter::BlockHashLogFilter {
            block_hashes: vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ],
            params: LogFilterParams {
                address: Some(vec![
                    H160::from_str("0000000000000000000000000000000000000000").unwrap(),
                    H160::from_str("0000000000000000000000000000000000000001").unwrap(),
                ]),
                topics: vec![
                    Some(vec![H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()]),
                    Some(vec![
                        H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                        H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    ]),
                    None,
                    None,
                ],
                offset: Some(1),
                limit: Some(2),
            },
        };

        assert_eq!(
            block_hash_filter.into_primitive(),
            Ok(primitive_block_hash_filter)
        );
    }
}
