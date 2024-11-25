// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    helpers::{maybe_vec_into, VariadicValue},
    types::{EpochNumber, Log, RpcAddress},
};
use cfx_types::{Space, H256, U256, U64};
use jsonrpc_core::Error as RpcError;
use primitives::filter::{LogFilter as PrimitiveFilter, LogFilterParams};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashSet;

const FILTER_BLOCK_HASH_LIMIT: usize = 128;

#[derive(PartialEq, Debug, Serialize, Deserialize, Eq, Hash, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CfxRpcLogFilter {
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
}

impl CfxRpcLogFilter {
    pub fn into_primitive(self) -> Result<PrimitiveFilter, RpcError> {
        // from_epoch, to_epoch
        let from_epoch = self
            .from_epoch
            .clone()
            .unwrap_or(EpochNumber::LatestState)
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

        let params = LogFilterParams {
            address,
            topics,
            trusted: false,
            space: Space::Native,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevertTo {
    pub revert_to: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfxFilterLog {
    Log(Log),
    ChainReorg(RevertTo),
}

impl Serialize for CfxFilterLog {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            CfxFilterLog::Log(ref log) => log.serialize(s),
            CfxFilterLog::ChainReorg(ref revert_to) => revert_to.serialize(s),
        }
    }
}

/// Results of the filter_changes RPC.
#[derive(Debug, PartialEq)]
pub enum CfxFilterChanges {
    /// New logs.
    Logs(Vec<CfxFilterLog>),
    /// New hashes (block or transactions)
    Hashes(Vec<H256>),
    /// Empty result
    Empty,
}

impl Serialize for CfxFilterChanges {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            CfxFilterChanges::Logs(ref logs) => logs.serialize(s),
            CfxFilterChanges::Hashes(ref hashes) => hashes.serialize(s),
            CfxFilterChanges::Empty => (&[] as &[Value]).serialize(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::types::{cfx::filter::RevertTo, CfxFilterLog, Log};

    use super::{
        super::RpcAddress, CfxRpcLogFilter, EpochNumber, VariadicValue,
    };
    use cfx_addr::Network;
    use cfx_types::{Space, H160, H256, U256, U64};
    use primitives::{
        epoch::EpochNumber as PrimitiveEpochNumber,
        filter::{LogFilter as PrimitiveFilter, LogFilterParams},
    };
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn test_serialize_filter() {
        let filter = CfxRpcLogFilter {
            from_epoch: None,
            to_epoch: None,
            from_block: None,
            to_block: None,
            block_hashes: None,
            address: None,
            topics: None,
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
             \"topics\":null\
             }"
        );

        let filter = CfxRpcLogFilter {
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
             ]\
             }"
        );
    }

    #[test]
    fn test_deserialize_filter() {
        let serialized = "{}";

        let result_filter = CfxRpcLogFilter {
            from_epoch: None,
            to_epoch: None,
            from_block: None,
            to_block: None,
            block_hashes: None,
            address: None,
            topics: None,
        };

        let deserialized_filter: CfxRpcLogFilter =
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
             ]\
        }";

        let result_filter = CfxRpcLogFilter {
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
        };

        let deserialized_filter: CfxRpcLogFilter =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_filter, result_filter);
    }

    #[test]
    fn test_convert_filter() {
        let epoch_filter = CfxRpcLogFilter {
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
                trusted: false,
                space: Space::Native,
            },
        };

        assert_eq!(epoch_filter.into_primitive(), Ok(primitive_epoch_filter));

        // -------------------------------------

        let block_number_filter = CfxRpcLogFilter {
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
                trusted: false,
                space: Space::Native,
            },
        };

        assert_eq!(
            block_number_filter.into_primitive(),
            Ok(primitive_block_number_filter)
        );

        // -------------------------------------

        let block_hash_filter = CfxRpcLogFilter {
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
                trusted: false,
                space: Space::Native,
            },
        };

        assert_eq!(
            block_hash_filter.into_primitive(),
            Ok(primitive_block_hash_filter)
        );
    }

    #[test]
    fn test_serialize_cfx_filter_log() {
        let mut logs = vec![];
        let log = Log {
            address: RpcAddress::try_from_h160(H160::from_str("13990122638b9132ca29c723bdf037f1a891a70c").unwrap(), Network::Test).unwrap(),
            topics: vec![
                H256::from_str("a6697e974e6a320f454390be03f74955e8978f1a6971ea6730542e37b66179bc").unwrap(),
                H256::from_str("4861736852656700000000000000000000000000000000000000000000000000").unwrap(),
            ],
            data: vec![].into(),
            block_hash: Some(H256::from_str("ed76641c68a1c641aee09a94b3b471f4dc0316efe5ac19cf488e2674cf8d05b5").unwrap()),
            epoch_number: Some(U256::from(0x4510c)),
            transaction_hash: Some(H256::default()),
            transaction_index: Some(U256::default()),
            transaction_log_index: Some(1.into()),
            log_index: Some(U256::from(1)),
            space: None,
        };

        logs.push(CfxFilterLog::Log(log));
        logs.push(CfxFilterLog::ChainReorg(RevertTo {
            revert_to: U256::from(1),
        }));
        let serialized = serde_json::to_string(&logs).unwrap();
        assert_eq!(
            serialized,
            r#"[{"address":"CFXTEST:TYPE.USER:AAK3WAKCPSF3CP0MFHDWHTTUG924VERHBUV9NMM3YC","topics":["0xa6697e974e6a320f454390be03f74955e8978f1a6971ea6730542e37b66179bc","0x4861736852656700000000000000000000000000000000000000000000000000"],"data":"0x","blockHash":"0xed76641c68a1c641aee09a94b3b471f4dc0316efe5ac19cf488e2674cf8d05b5","epochNumber":"0x4510c","transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionIndex":"0x0","logIndex":"0x1","transactionLogIndex":"0x1"},{"revertTo":"0x1"}]"#
        );
    }
}
