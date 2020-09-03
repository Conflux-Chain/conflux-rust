// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::EpochNumber;
use cfx_types::{H160, H256, U64};
use jsonrpc_core::Error as RpcError;
use primitives::filter::Filter as PrimitiveFilter;
use serde::{
    de::{DeserializeOwned, Error},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::{from_value, Value};

const FILTER_BLOCK_HASH_LIMIT: usize = 128;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum VariadicValue<T> {
    /// None
    Null,
    /// Single
    Single(T),
    /// List
    Multiple(Vec<T>),
}

impl<T> Into<Option<Vec<T>>> for VariadicValue<T> {
    fn into(self) -> Option<Vec<T>> {
        match self {
            VariadicValue::Null => None,
            VariadicValue::Single(x) => Some(vec![x]),
            VariadicValue::Multiple(xs) => Some(xs),
        }
    }
}

impl<T> Serialize for VariadicValue<T>
where T: Serialize
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match &self {
            &VariadicValue::Null => serializer.serialize_none(),
            &VariadicValue::Single(x) => x.serialize(serializer),
            &VariadicValue::Multiple(xs) => xs.serialize(serializer),
        }
    }
}

impl<'a, T> Deserialize<'a> for VariadicValue<T>
where T: DeserializeOwned
{
    fn deserialize<D>(deserializer: D) -> Result<VariadicValue<T>, D::Error>
    where D: Deserializer<'a> {
        let v: Value = Deserialize::deserialize(deserializer)?;

        if v.is_null() {
            return Ok(VariadicValue::Null);
        }

        from_value(v.clone())
            .map(VariadicValue::Single)
            .or_else(|_| from_value(v).map(VariadicValue::Multiple))
            .map_err(|err| {
                D::Error::custom(format!(
                    "Invalid variadic value type: {}",
                    err
                ))
            })
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Eq, Hash, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Filter {
    /// Search will be applied from this epoch number.
    pub from_epoch: Option<EpochNumber>,

    /// Till this epoch number.
    pub to_epoch: Option<EpochNumber>,

    /// Search will be applied in these blocks if given.
    /// This will override from/to_epoch fields.
    pub block_hashes: Option<Vec<H256>>,

    /// Search addresses.
    ///
    /// If None, match all.
    /// If specified, log must be produced by one of these addresses.
    pub address: Option<VariadicValue<H160>>,

    /// Search topics.
    ///
    /// Logs can have 4 topics: the function signature and up to 3 indexed
    /// event arguments. The elements of `topics` match the corresponding
    /// log topics. Example: ["0xA", null, ["0xB", "0xC"], null] matches
    /// logs with "0xA" as the 1st topic AND ("0xB" OR "0xC") as the 3rd
    /// topic. If None, match all.
    pub topics: Option<Vec<VariadicValue<H256>>>,

    /// Logs limit
    ///
    /// If None, return all logs
    /// If specified, should only return *last* `n` logs.
    pub limit: Option<U64>,
}

// helper implementing automatic Option<Vec<A>> -> Option<Vec<B>> conversion
fn maybe_vec_into<A, B>(src: &Option<Vec<A>>) -> Option<Vec<B>>
where A: Clone + Into<B> {
    src.clone().map(|x| x.into_iter().map(Into::into).collect())
}

impl Filter {
    pub fn into_primitive(self) -> Result<PrimitiveFilter, RpcError> {
        // from_epoch, to_epoch
        let from_epoch = self
            .from_epoch
            .unwrap_or(EpochNumber::LatestCheckpoint)
            .into();

        let to_epoch = self.to_epoch.unwrap_or(EpochNumber::LatestState).into();

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
        let address = self.address.and_then(Into::into);
        let limit = self.limit.map(|x| x.as_u64() as usize);

        Ok(PrimitiveFilter {
            from_epoch,
            to_epoch,
            block_hashes,
            address,
            topics,
            limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{EpochNumber, Filter, VariadicValue};
    use cfx_types::{Address, H160, H256, U64};
    use primitives::{
        epoch::EpochNumber as PrimitiveEpochNumber,
        filter::Filter as PrimitiveFilter,
    };
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn test_serialize_variadic_value() {
        let value: VariadicValue<u64> = VariadicValue::Null;
        let serialized_value = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized_value, "null");

        let value = VariadicValue::Single(1);
        let serialized_value = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized_value, "1");

        let value = VariadicValue::Multiple(vec![1, 2, 3, 4]);
        let serialized_value = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized_value, "[1,2,3,4]");

        let value = VariadicValue::Multiple(vec![
            VariadicValue::Null,
            VariadicValue::Single(1),
            VariadicValue::Multiple(vec![2, 3]),
            VariadicValue::Single(4),
        ]);
        let serialized_value = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized_value, "[null,1,[2,3],4]");
    }

    #[test]
    fn test_deserialize_variadic_value() {
        let serialized = "null";
        let deserialized_value: VariadicValue<u64> =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_value, VariadicValue::Null);

        let serialized = "1";
        let deserialized_value: VariadicValue<u64> =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_value, VariadicValue::Single(1));

        let serialized = "[1,2,3,4]";
        let deserialized_value: VariadicValue<u64> =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(
            deserialized_value,
            VariadicValue::Multiple(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn test_serialize_filter() {
        let filter = Filter {
            from_epoch: None,
            to_epoch: None,
            block_hashes: None,
            address: None,
            topics: None,
            limit: None,
        };

        let serialized_filter = serde_json::to_string(&filter).unwrap();

        assert_eq!(
            serialized_filter,
            "{\
             \"fromEpoch\":null,\
             \"toEpoch\":null,\
             \"blockHashes\":null,\
             \"address\":null,\
             \"topics\":null,\
             \"limit\":null\
             }"
        );

        let filter = Filter {
            from_epoch: Some(1000.into()),
            to_epoch: Some(EpochNumber::LatestState),
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                Address::from_str("0000000000000000000000000000000000000000").unwrap(),
                Address::from_str("0000000000000000000000000000000000000001").unwrap()
            ])),
            topics: Some(vec![
                VariadicValue::Single(H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()),
                VariadicValue::Multiple(vec![
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                ]),
            ]),
            limit: Some(U64::from(2)),
        };

        let serialized_filter = serde_json::to_string(&filter).unwrap();

        assert_eq!(
            serialized_filter,
            "{\
             \"fromEpoch\":\"0x3e8\",\
             \"toEpoch\":\"latest_state\",\
             \"blockHashes\":[\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"],\
             \"address\":[\"0x0000000000000000000000000000000000000000\",\"0x0000000000000000000000000000000000000001\"],\
             \"topics\":[\
                \"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\",\
                [\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\",\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\"]\
             ],\
             \"limit\":\"0x2\"\
             }"
        );
    }

    #[test]
    fn test_deserialize_filter() {
        let serialized = "{}";

        let result_filter = Filter {
            from_epoch: None,
            to_epoch: None,
            block_hashes: None,
            address: None,
            topics: None,
            limit: None,
        };

        let deserialized_filter: Filter =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_filter, result_filter);

        let serialized = "{\
             \"fromEpoch\":\"0x3e8\",\
             \"toEpoch\":\"latest_state\",\
             \"blockHashes\":[\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"],\
             \"address\":[\"0x0000000000000000000000000000000000000000\",\"0x0000000000000000000000000000000000000001\"],\
             \"topics\":[\
                \"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\",\
                [\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\",\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\"]\
             ],\
             \"limit\":\"0x2\"\
        }";

        let result_filter = Filter {
            from_epoch: Some(1000.into()),
            to_epoch: Some(EpochNumber::LatestState),
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                H160::from_str("0000000000000000000000000000000000000000").unwrap(),
                H160::from_str("0000000000000000000000000000000000000001").unwrap()
            ])),
            topics: Some(vec![
                VariadicValue::Single(H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()),
                VariadicValue::Multiple(vec![
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                ]),
            ]),
            limit: Some(U64::from(2)),
        };

        let deserialized_filter: Filter =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_filter, result_filter);
    }

    #[test]
    fn test_convert_filter() {
        let filter = Filter {
            from_epoch: None,
            to_epoch: None,
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                H160::from_str("0000000000000000000000000000000000000000").unwrap(),
                H160::from_str("0000000000000000000000000000000000000001").unwrap()
            ])),
            topics: Some(vec![
                VariadicValue::Single(H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap()),
                VariadicValue::Multiple(vec![
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                    H256::from_str("d397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5").unwrap(),
                ]),
            ]),
            limit: Some(U64::from(2)),
        };

        let primitive_filter = PrimitiveFilter {
            from_epoch: PrimitiveEpochNumber::LatestCheckpoint,
            to_epoch: PrimitiveEpochNumber::LatestState,
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            address: Some(vec![
                H160::from_str("0000000000000000000000000000000000000000").unwrap(),
                H160::from_str("0000000000000000000000000000000000000001").unwrap()
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
            limit: Some(2),
        };

        assert_eq!(filter.into_primitive(), Ok(primitive_filter));
    }
}
