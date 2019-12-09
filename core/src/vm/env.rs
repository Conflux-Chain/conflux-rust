// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Environment information for transaction execution.

use cfx_types::{Address, H256, U256};
use primitives::BlockNumber;
use std::sync::Arc;

/// Simple vector of hashes, should be at most 256 items large, can be smaller
/// if being used for a block whose number is less than 257.
pub type LastHashes = Vec<H256>;

/// Information concerning the execution environment for a
/// message-call/contract-creation.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// The block number.
    pub number: BlockNumber,
    /// The block author.
    pub author: Address,
    /// The block timestamp.
    pub timestamp: u64,
    /// The block difficulty.
    pub difficulty: U256,
    /// The block gas limit.
    pub gas_limit: U256,
    /// The last 256 block hashes.
    pub last_hashes: Arc<LastHashes>,
    /// The gas used.
    pub gas_used: U256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_can_be_created_as_default() {
        let default_env = Env::default();

        assert_eq!(default_env.number, 0);
        assert_eq!(default_env.author, Address::default());
        assert_eq!(default_env.timestamp, 0);
        assert_eq!(default_env.difficulty, 0.into());
        assert_eq!(default_env.gas_limit, 0.into());
        assert!(default_env.last_hashes.is_empty());
        assert_eq!(default_env.gas_used, 0.into());
    }
}
