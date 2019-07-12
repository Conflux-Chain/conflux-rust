// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{H160, H256, U64};
use cfx_types::U64 as CfxU64;
use primitives::filter::Filter as PrimitiveFilter;

#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    /// Search will be applied from this epoch number.
    pub from_epoch: U64,

    /// Till this epoch number.
    pub to_epoch: U64,

    /// Search will be applied in these blocks if given.
    /// This will override from/to_epoch fields.
    pub block_hashes: Option<Vec<H256>>,

    /// Search addresses.
    ///
    /// If None, match all.
    /// If specified, log must be produced by one of these addresses.
    pub address: Option<Vec<H160>>,

    /// Search topics.
    ///
    /// If None, match all.
    /// If specified, log must contain one of these topics.
    pub topics: Vec<Option<Vec<H256>>>,

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
    // pub fn new(f: &PrimitiveFilter) -> Self {
    //     Filter {
    //         from_epoch: f.from_epoch.into(),
    //         to_epoch: f.to_epoch.into(),
    //         block_hashes: maybe_vec_into(&f.block_hashes),
    //         address: maybe_vec_into(&f.address),
    //         topics: f.topics.iter().map(maybe_vec_into).collect(),
    //         limit: f.limit.map(U64::from),
    //     }
    // }

    pub fn into_primitive(self) -> PrimitiveFilter {
        PrimitiveFilter {
            from_epoch: self.from_epoch.into(),
            to_epoch: self.to_epoch.into(),
            block_hashes: maybe_vec_into(&self.block_hashes),
            address: maybe_vec_into(&self.address),
            topics: self.topics.iter().map(maybe_vec_into).collect(),
            limit: self.limit.map(Into::into),
        }
    }
}

impl Into<PrimitiveFilter> for Filter {
    fn into(self) -> PrimitiveFilter { self.into_primitive() }
}

#[cfg(test)]
mod tests {
    use super::Filter;
    use primitives::filter::Filter as PrimitiveFilter;
    use serde_json;

    #[test]
    fn test_serialize_filter() {
        let filter = Filter {
            from_epoch: 0.into(),
            to_epoch: 0.into(),
            block_hashes: None,
            address: None,
            topics: vec![],
            limit: None,
        };

        let serialized_filter = serde_json::to_string(&filter).unwrap();

        assert_eq!(
            serialized_filter,
            "{\
             \"fromEpoch\":\"0x0\",\
             \"toEpoch\":\"0x0\",\
             \"blockHashes\":null,\
             \"address\":null,\
             \"topics\":[],\
             \"limit\":null\
             }"
        );

        let filter = Filter {
            from_epoch: 1.into(),
            to_epoch: 1000.into(),
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
                Some(vec![])
            ],
            limit: Some(2.into()),
        };

        let serialized_filter = serde_json::to_string(&filter).unwrap();

        assert_eq!(
            serialized_filter,
            "{\
             \"fromEpoch\":\"0x1\",\
             \"toEpoch\":\"0x3e8\",\
             \"blockHashes\":[\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"],\
             \"address\":[\"0x0000000000000000000000000000000000000000\",\"0x0000000000000000000000000000000000000001\"],\
             \"topics\":[[\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\"],[]],\
             \"limit\":\"0x2\"\
             }"
        );
    }

    #[test]
    fn test_deserialize_filter() {
        let serialized = "{\
             \"fromEpoch\":\"0x1\",\
             \"toEpoch\":\"0x3e8\",\
             \"blockHashes\":[\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"],\
             \"address\":[\"0x0000000000000000000000000000000000000000\",\"0x0000000000000000000000000000000000000001\"],\
             \"topics\":[[\"0xd397b3b043d87fcd6fad1291ff0bfd16401c274896d8c63a923727f077b8e0b5\"],[]],\
             \"limit\":\"0x2\"\
             }";

        let result_filter = Filter {
            from_epoch: 1.into(),
            to_epoch: 1000.into(),
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
                Some(vec![])
            ],
            limit: Some(2.into()),
        };

        let deserialized_filter: Filter =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_filter, result_filter);
    }

    #[test]
    fn test_convert_filter() {
        let filter = Filter {
            from_epoch: 1.into(),
            to_epoch: 1000.into(),
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
                Some(vec![])
            ],
            limit: Some(2.into()),
        };

        let primitive_filter = PrimitiveFilter {
            from_epoch: 1 as u64,
            to_epoch: 1000 as u64,
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
                Some(vec![])
            ],
            limit: Some(2 as usize),
        };

        assert_eq!(filter.into_primitive(), primitive_filter);
    }
}
