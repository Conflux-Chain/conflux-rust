// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Configuration for application cache sizes.
/// All	values are represented in MB.
use std::cmp::max;

pub const DEFAULT_LEDGER_CACHE_SIZE: usize = 1024;
const MIN_LEDGER_CACHE_MB: usize = 4;

pub const DEFAULT_INVALID_BLOCK_HASH_CACHE_SIZE_IN_COUNT: usize = 32 * 1024;

#[derive(Debug, PartialEq)]
pub struct CacheConfig {
    /// Size of ledger cache.
    pub ledger: usize,
    /// The maximum number of cached invalid block hashes
    pub invalid_block_hashes_cache_size_in_count: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig::new(
            DEFAULT_LEDGER_CACHE_SIZE,
            DEFAULT_INVALID_BLOCK_HASH_CACHE_SIZE_IN_COUNT,
        )
    }
}

impl CacheConfig {
    /// Creates new cache config with given details.
    pub fn new(
        ledger: usize, invalid_block_hashes_cache_size_in_count: usize,
    ) -> Self {
        CacheConfig {
            ledger,
            invalid_block_hashes_cache_size_in_count,
        }
    }

    /// Size of the ledger cache.
    pub fn ledger_mb(&self) -> usize { max(self.ledger, MIN_LEDGER_CACHE_MB) }
}
