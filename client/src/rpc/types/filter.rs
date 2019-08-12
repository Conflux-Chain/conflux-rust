// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{EpochNumber, H160, H256, U64};
use cfx_types::U64 as CfxU64;
use primitives::filter::Filter as PrimitiveFilter;

use serde::{
    de::{DeserializeOwned, Error},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::{from_value, Value};

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
#[serde(rename_all = "camelCase")]
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

impl Into<u64> for U64 {
    fn into(self) -> u64 {
        let x: CfxU64 = self.into();
        x.as_u64()
    }
}

impl Into<usize> for U64 {
    fn into(self) -> usize {
        let x: CfxU64 = self.into();
        x.as_usize()
    }
}

impl Filter {
    pub fn into_primitive(self) -> PrimitiveFilter {
        let address = self.address.and_then(Into::into);

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

        PrimitiveFilter {
            from_epoch: self.from_epoch.unwrap_or(EpochNumber::Earliest).into(),
            to_epoch: self.to_epoch.unwrap_or(EpochNumber::LatestMined).into(),
            block_hashes: maybe_vec_into(&self.block_hashes),
            address: maybe_vec_into(&address),
            topics: topics.iter().map(maybe_vec_into).collect(),
            limit: self.limit.map(Into::into),
        }
    }
}

impl Into<PrimitiveFilter> for Filter {
    fn into(self) -> PrimitiveFilter { self.into_primitive() }
}

#[cfg(test)]
mod tests {
    use super::{EpochNumber, Filter, VariadicValue};
    use primitives::{
        epoch::EpochNumber as PrimitiveEpochNumber,
        filter::Filter as PrimitiveFilter,
    };
    use serde_json;

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
                "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".into(),
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".into()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                "0x0000000000000000000000000000000000000000".into(),
                "0x0000000000000000000000000000000000000001".into()
            ])),
            topics: Some(vec![
                VariadicValue::Single("0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into()),
                VariadicValue::Multiple(vec![
                    "0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into(),
                    "0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into(),
                ]),
            ]),
            limit: Some(2.into()),
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
                "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".into(),
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".into()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                "0x0000000000000000000000000000000000000000".into(),
                "0x0000000000000000000000000000000000000001".into()
            ])),
            topics: Some(vec![
                VariadicValue::Single("0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into()),
                VariadicValue::Multiple(vec![
                    "0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into(),
                    "0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into(),
                ]),
            ]),
            limit: Some(2.into()),
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
                "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".into(),
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".into()
            ]),
            address: Some(VariadicValue::Multiple(vec![
                "0x0000000000000000000000000000000000000000".into(),
                "0x0000000000000000000000000000000000000001".into()
            ])),
            topics: Some(vec![
                VariadicValue::Single("0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into()),
                VariadicValue::Multiple(vec![
                    "0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into(),
                    "0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into(),
                ]),
            ]),
            limit: Some(2.into()),
        };

        let primitive_filter = PrimitiveFilter {
            from_epoch: PrimitiveEpochNumber::Earliest,
            to_epoch: PrimitiveEpochNumber::LatestMined,
            block_hashes: Some(vec![
                "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".into(),
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".into()
            ]),
            address: Some(vec![
                "0x0000000000000000000000000000000000000000".into(),
                "0x0000000000000000000000000000000000000001".into()
            ]),
            topics: vec![
                Some(vec!["0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into()]),
                Some(vec![
                    "0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into(),
                    "0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5".into(),
                ]),
                None,
                None,
            ],
            limit: Some(2 as usize),
        };

        assert_eq!(filter.into_primitive(), primitive_filter);
    }
}
