// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! Trace filter deserialization.

use crate::BlockNumber;
use cfx_parity_trace_types::TraceFilter as PrimitiveTraceFilter;
use cfx_types::{Space, H160};
use jsonrpc_core::Error as RpcError;
use primitives::EpochNumber;
use serde::Deserialize;
use std::convert::TryInto;

/// Trace filter
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct TraceFilter {
    /// From block
    pub from_block: Option<BlockNumber>,
    /// To block
    pub to_block: Option<BlockNumber>,
    /// From address
    pub from_address: Option<Vec<H160>>,
    /// To address
    pub to_address: Option<Vec<H160>>,
    /// Output offset
    pub after: Option<usize>,
    /// Output amount
    pub count: Option<usize>,
}

impl TraceFilter {
    pub fn into_primitive(self) -> Result<PrimitiveTraceFilter, RpcError> {
        let from_epoch = match self.from_block {
            // FIXME(thegaram): this is probably not consistent with eth
            // FIXME(lpl): Support BlockHash?
            None => EpochNumber::LatestCheckpoint,
            Some(bn) => bn.try_into()?,
        };

        let to_epoch = match self.to_block {
            None => EpochNumber::LatestState,
            Some(bn) => bn.try_into()?,
        };

        Ok(PrimitiveTraceFilter {
            from_epoch,
            to_epoch,
            block_hashes: None,
            action_types: Default::default(),
            from_address: self
                .from_address
                .map_or_else(Default::default, Into::into),
            to_address: self
                .to_address
                .map_or_else(Default::default, Into::into),
            after: self.after,
            count: self.count,
            space: Space::Ethereum,
        })
    }
}
