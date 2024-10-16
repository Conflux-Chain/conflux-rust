// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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

use cfx_types::U256;
use serde::{Serialize, Serializer};

/// Sync info
#[derive(Default, Debug, Serialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SyncInfo {
    /// Starting block
    pub starting_block: U256,
    /// Current block
    pub current_block: U256,
    /// Highest block seen so far
    pub highest_block: U256,
    /// Warp sync snapshot chunks total.
    pub warp_chunks_amount: Option<U256>,
    /// Warp sync snpashot chunks processed.
    pub warp_chunks_processed: Option<U256>,
}

/// Sync status
#[derive(Debug, PartialEq, Clone)]
pub enum SyncStatus {
    /// Info when syncing
    Info(SyncInfo),
    /// Not syncing
    None,
}

impl Serialize for SyncStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            SyncStatus::Info(ref info) => info.serialize(serializer),
            SyncStatus::None => false.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SyncInfo, SyncStatus};
    use serde_json;

    #[test]
    fn test_serialize_sync_info() {
        let t = SyncInfo::default();
        let serialized = serde_json::to_string(&t).unwrap();
        assert_eq!(
            serialized,
            r#"{"startingBlock":"0x0","currentBlock":"0x0","highestBlock":"0x0","warpChunksAmount":null,"warpChunksProcessed":null}"#
        );
    }

    #[test]
    fn test_serialize_sync_status() {
        let t = SyncStatus::None;
        let serialized = serde_json::to_string(&t).unwrap();
        assert_eq!(serialized, "false");

        let t = SyncStatus::Info(SyncInfo::default());
        let serialized = serde_json::to_string(&t).unwrap();
        assert_eq!(
            serialized,
            r#"{"startingBlock":"0x0","currentBlock":"0x0","highestBlock":"0x0","warpChunksAmount":null,"warpChunksProcessed":null}"#
        );
    }
}
