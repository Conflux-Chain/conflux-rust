// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Configuration for application cache sizes.
/// All	values are represented in MB.
use std::cmp::max;

const MIN_DB_CACHE_MB: usize = 8;
const MIN_LEDGER_CACHE_MB: usize = 4;
const DEFAULT_DB_CACHE_SIZE: usize = 128;
const DEFAULT_LEDGER_CACHE_SIZE: usize = 2048;

#[derive(Debug, PartialEq)]
pub struct CacheConfig {
    /// Size of rocksDB cache.
    pub db: usize,
    /// Size of ledger cache.
    pub ledger: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig::new(DEFAULT_DB_CACHE_SIZE, DEFAULT_LEDGER_CACHE_SIZE)
    }
}

impl CacheConfig {
    /// Creates new cache config with gitven details.
    pub fn new(db: usize, ledger: usize) -> Self { CacheConfig { db, ledger } }

    /// Size of db cache.
    #[allow(dead_code)]
    pub fn db_cache_size(&self) -> usize { max(MIN_DB_CACHE_MB, self.db) }

    /// Size of the ledger cache.
    pub fn ledger_mb(&self) -> usize { max(self.ledger, MIN_LEDGER_CACHE_MB) }
}
