// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Configuration for application cache sizes.
/// All	values are represented in MB.
use std::cmp::max;

pub const DEFAULT_LEDGER_CACHE_SIZE: usize = 1024;
const MIN_LEDGER_CACHE_MB: usize = 4;

#[derive(Debug, PartialEq)]
pub struct CacheConfig {
    /// Size of ledger cache.
    pub ledger: usize,
}

impl Default for CacheConfig {
    fn default() -> Self { CacheConfig::new(DEFAULT_LEDGER_CACHE_SIZE) }
}

impl CacheConfig {
    /// Creates new cache config with gitven details.
    pub fn new(ledger: usize) -> Self { CacheConfig { ledger } }

    /// Size of the ledger cache.
    pub fn ledger_mb(&self) -> usize { max(self.ledger, MIN_LEDGER_CACHE_MB) }
}
