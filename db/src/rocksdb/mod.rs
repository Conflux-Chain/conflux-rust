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

extern crate core;
extern crate kvdb_rocksdb;

use self::kvdb_rocksdb::{CompactionProfile, Database, DatabaseConfig};
use std::{io, path::Path, str::FromStr, sync::Arc};

pub struct SystemDB {
    // This is the general db that will be shared and used by
    // all the special db at upper layer.
    key_value: Arc<Database>,
}

impl SystemDB {
    pub fn key_value(&self) -> &Arc<Database> { &self.key_value }

    pub fn new(kvdb: Arc<Database>) -> Self { Self { key_value: kvdb } }
}

/// db compaction profile
#[derive(Debug, PartialEq, Clone)]
pub enum DatabaseCompactionProfile {
    /// Try to determine compaction profile automatically
    Auto,
    /// SSD compaction profile
    SSD,
    /// HDD or other slow storage io compaction profile
    HDD,
}

impl Default for DatabaseCompactionProfile {
    fn default() -> Self { DatabaseCompactionProfile::Auto }
}

impl FromStr for DatabaseCompactionProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(DatabaseCompactionProfile::Auto),
            "ssd" => Ok(DatabaseCompactionProfile::SSD),
            "hdd" => Ok(DatabaseCompactionProfile::HDD),
            _ => Err(
                "Invalid compaction profile given. Expected default/hdd/ssd."
                    .into(),
            ),
        }
    }
}

pub fn compaction_profile(
    profile: &DatabaseCompactionProfile, db_path: &Path,
) -> CompactionProfile {
    match profile {
        &DatabaseCompactionProfile::Auto => CompactionProfile::auto(db_path),
        &DatabaseCompactionProfile::SSD => CompactionProfile::ssd(),
        &DatabaseCompactionProfile::HDD => CompactionProfile::hdd(),
    }
}

pub fn db_config(
    path: &Path, db_cache_size: Option<usize>,
    db_compaction: DatabaseCompactionProfile, columns: Option<u32>,
    disable_wal: bool,
) -> DatabaseConfig
{
    let mut db_config = DatabaseConfig::with_columns(columns);

    db_config.memory_budget = db_cache_size;
    db_config.compaction = compaction_profile(&db_compaction, &path);
    db_config.disable_wal = disable_wal;

    db_config
}

pub fn open_database(
    path: &str, config: &DatabaseConfig,
) -> io::Result<Arc<SystemDB>> {
    let db = match Database::open(config, path) {
        Ok(db) => {
            info!("Open db successfully ({:?})", path);
            db
        }
        Err(e) => {
            warn!("Failed to open db ({:?})", path);
            return Err(e);
        }
    };

    let sys_db = SystemDB::new(Arc::new(db));

    Ok(Arc::new(sys_db))
}
