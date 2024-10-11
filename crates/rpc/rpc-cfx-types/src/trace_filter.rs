// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::trace::ActionType;
use crate::EpochNumber;
use cfx_parity_trace_types::TraceFilter as PrimitiveTraceFilter;
use cfx_rpc_primitives::{maybe_vec_into, VariadicValue};
use cfx_types::{Address, Space, H256, U64};
use jsonrpc_core::Error as RpcError;
use serde::{Deserialize, Serialize};

const FILTER_BLOCK_HASH_LIMIT: usize = 128;

#[derive(PartialEq, Debug, Serialize, Deserialize, Eq, Hash, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceFilter {
    /// Search will be applied from this epoch number.
    pub from_epoch: Option<EpochNumber>,

    /// Till this epoch number.
    pub to_epoch: Option<EpochNumber>,

    /// Search from_address.
    pub from_address: Option<VariadicValue<Address>>,
    /// Search to_address.
    pub to_address: Option<VariadicValue<Address>>,

    /// Search will be applied in these blocks if given.
    /// This will override from/to_epoch fields.
    pub block_hashes: Option<Vec<H256>>,

    /// Search action.
    ///
    /// If None, match all.
    /// If specified, trace must match one of these action types.
    pub action_types: Option<VariadicValue<ActionType>>,

    /// The offset trace number.
    pub after: Option<U64>,

    /// The number of traces to display in a batch.
    pub count: Option<U64>,
}

impl TraceFilter {
    pub fn into_primitive(self) -> Result<PrimitiveTraceFilter, RpcError> {
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

        // address, limit
        let action_types = match self.action_types {
            None | Some(VariadicValue::Null) => vec![],
            Some(VariadicValue::Single(x)) => vec![x.into()],
            Some(VariadicValue::Multiple(xs)) => {
                xs.into_iter().map(|x| x.into()).collect()
            }
        };

        Ok(PrimitiveTraceFilter {
            from_epoch,
            to_epoch,
            block_hashes,
            from_address: self
                .from_address
                .and_then(Into::into)
                .unwrap_or_else(Vec::new)
                .into(),
            to_address: self
                .to_address
                .and_then(Into::into)
                .unwrap_or_else(Vec::new)
                .into(),
            action_types: action_types.into(),
            after: self.after.map(|n| n.as_usize()),
            count: self.count.map(|n| n.as_usize()),
            space: Space::Native,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::trace::ActionType, EpochNumber, TraceFilter, VariadicValue,
    };
    use cfx_parity_trace_types::{
        ActionType as PrimitiveActionType, TraceFilter as PrimitiveTraceFilter,
    };
    use cfx_types::{Address, Space, H256, U64};
    use primitives::epoch::EpochNumber as PrimitiveEpochNumber;
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn test_serialize_filter() {
        let filter = TraceFilter {
            from_epoch: None,
            to_epoch: None,
            from_address: None,
            to_address: None,
            block_hashes: None,
            action_types: None,
            after: None,
            count: None,
        };

        let serialized_filter = serde_json::to_string(&filter).unwrap();

        assert_eq!(
            serialized_filter,
            "{\
             \"fromEpoch\":null,\
             \"toEpoch\":null,\
             \"fromAddress\":null,\
             \"toAddress\":null,\
             \"blockHashes\":null,\
             \"actionTypes\":null,\
             \"after\":null,\
             \"count\":null\
             }"
        );

        let filter = TraceFilter {
            from_epoch: Some(1000.into()),
            to_epoch: Some(EpochNumber::LatestState),
            from_address: Some(VariadicValue::Multiple(vec![Address::zero()].into())),
            to_address: Some(VariadicValue::Multiple(vec![Address::zero()].into())),
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            action_types: Some(VariadicValue::Multiple(vec![
                ActionType::Call,
                ActionType::CreateResult,
            ])),
            after: Some(U64::from(2)),
            count: Some(U64::from(3)),
        };

        let serialized_filter = serde_json::to_string(&filter).unwrap();

        assert_eq!(
            serialized_filter,
            "{\
             \"fromEpoch\":\"0x3e8\",\
             \"toEpoch\":\"latest_state\",\
             \"fromAddress\":[\"0x0000000000000000000000000000000000000000\"],\
             \"toAddress\":[\"0x0000000000000000000000000000000000000000\"],\
             \"blockHashes\":[\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"],\
             \"actionTypes\":[\"call\",\"create_result\"],\
             \"after\":\"0x2\",\
             \"count\":\"0x3\"\
             }"
        );
    }

    #[test]
    fn test_deserialize_filter() {
        let serialized = "{}";

        let result_filter = TraceFilter {
            from_epoch: None,
            to_epoch: None,
            from_address: None,
            to_address: None,
            block_hashes: None,
            action_types: None,
            after: None,
            count: None,
        };

        let deserialized_filter: TraceFilter =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_filter, result_filter);

        let serialized = "{\
             \"fromEpoch\":\"0x3e8\",\
             \"toEpoch\":\"latest_state\",\
             \"fromAddress\":[\"0x0000000000000000000000000000000000000000\"],\
             \"toAddress\":[\"0x0000000000000000000000000000000000000000\"],\
             \"blockHashes\":[\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\"],\
             \"actionTypes\":[\"call\",\"create_result\"],\
             \"after\":\"0x2\",\
             \"count\":\"0x3\"\
        }";

        let result_filter = TraceFilter {
            from_epoch: Some(1000.into()),
            to_epoch: Some(EpochNumber::LatestState),
            from_address: Some(VariadicValue::Multiple(vec![Address::zero()].into())),
            to_address: Some(VariadicValue::Multiple(vec![Address::zero()].into())),
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            action_types: Some(VariadicValue::Multiple(vec![
                ActionType::Call,
                ActionType::CreateResult,
            ])),
            after: Some(U64::from(2)),
            count: Some(U64::from(3)),
        };

        let deserialized_filter: TraceFilter =
            serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized_filter, result_filter);
    }

    #[test]
    fn test_convert_filter() {
        let filter = TraceFilter {
            from_epoch: None,
            to_epoch: None,
            from_address: Some(VariadicValue::Multiple(vec![Address::zero()].into())),
            to_address: Some(VariadicValue::Multiple(vec![Address::zero()].into())),
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            action_types: Some(VariadicValue::Multiple(vec![
                ActionType::Call,
                ActionType::CreateResult,
            ])),
            after: Some(U64::from(2)),
            count: Some(U64::from(3)),
        };

        let primitive_filter = PrimitiveTraceFilter {
            from_epoch: PrimitiveEpochNumber::LatestCheckpoint,
            to_epoch: PrimitiveEpochNumber::LatestState,
            from_address: vec![Address::zero()].into(),
            to_address: vec![Address::zero()].into(),
            block_hashes: Some(vec![
                H256::from_str("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap(),
                H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
            ]),
            action_types: vec![PrimitiveActionType::Call, PrimitiveActionType::CreateResult].into(),
            after: Some(2),
            count:Some(3),
            space: Space::Native
        };

        assert_eq!(filter.into_primitive(), Ok(primitive_filter));
    }
}
