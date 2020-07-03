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

use std::{cmp, collections::HashMap, error, fs, io, mem, path::Path, result};

use parking_lot::{Mutex, MutexGuard, RwLock};
use rocksdb::{
    BlockBasedOptions, CFHandle, ColumnFamilyOptions, DBOptions, ReadOptions,
    Writable, WriteBatch, WriteOptions, DB,
};

use fs_swap::{swap, swap_nonatomic};
use kvdb::{DBKey, DBOp, DBTransaction, DBValue, KeyValueDB};
use log::{debug, warn};

use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
use parity_util_mem::{
    MallocSizeOf as ParityMallocSizeOf,
    MallocSizeOfOps as ParityMallocSizeOfOps,
};
#[cfg(target_os = "linux")]
use regex::Regex;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;

type DBError = String;
type KeyValuePair = (Box<[u8]>, Box<[u8]>);
fn other_io_err<E>(e: E) -> io::Error
where E: Into<Box<dyn error::Error + Send + Sync>> {
    io::Error::new(io::ErrorKind::Other, e)
}

const KB: usize = 1024;
const MB: usize = 1024 * KB;
const DB_DEFAULT_MEMORY_BUDGET_MB: usize = 128;

#[derive(MallocSizeOfDerive)]
enum KeyState {
    Insert(DBValue),
    Delete,
}

/// Compaction profile for the database settings
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct CompactionProfile {
    /// L0-L1 target file size
    pub initial_file_size: u64,
    /// block size
    pub block_size: usize,
    /// rate limiter for background flushes and compactions, bytes/sec, if any
    pub write_rate_limit: Option<u64>,
}

impl Default for CompactionProfile {
    /// Default profile suitable for most storage
    fn default() -> CompactionProfile { CompactionProfile::ssd() }
}

/// Given output of df command return Linux rotational flag file path.
#[cfg(target_os = "linux")]
pub fn rotational_from_df_output(df_out: Vec<u8>) -> Option<PathBuf> {
    use std::str;
    str::from_utf8(df_out.as_slice())
        .ok()
        // Get the drive name.
        .and_then(|df_str| {
            Regex::new(r"/dev/(sd[:alpha:]{1,2})")
                .ok()
                .and_then(|re| re.captures(df_str))
                .and_then(|captures| captures.get(1))
        })
        // Generate path e.g. /sys/block/sda/queue/rotational
        .map(|drive_path| {
            let mut p = PathBuf::from("/sys/block");
            p.push(drive_path.as_str());
            p.push("queue/rotational");
            p
        })
}

impl CompactionProfile {
    /// Attempt to determine the best profile automatically, only Linux for now.
    #[cfg(target_os = "linux")]
    pub fn auto(db_path: &Path) -> CompactionProfile {
        use std::io::Read;
        let hdd_check_file = db_path
            .to_str()
            .and_then(|path_str| Command::new("df").arg(path_str).output().ok())
            .and_then(|df_res| match df_res.status.success() {
                true => Some(df_res.stdout),
                false => None,
            })
            .and_then(rotational_from_df_output);
        // Read out the file and match compaction profile.
        if let Some(hdd_check) = hdd_check_file {
            if let Ok(mut file) = File::open(hdd_check.as_path()) {
                let mut buffer = [0; 1];
                if file.read_exact(&mut buffer).is_ok() {
                    // 0 means not rotational.
                    if buffer == [48] {
                        return Self::ssd();
                    }
                    // 1 means rotational.
                    if buffer == [49] {
                        return Self::hdd();
                    }
                }
            }
        }
        // Fallback if drive type was not determined.
        Self::default()
    }

    /// Just default for other platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn auto(_db_path: &Path) -> CompactionProfile { Self::default() }

    /// Default profile suitable for SSD storage
    pub fn ssd() -> CompactionProfile {
        CompactionProfile {
            initial_file_size: 64 * MB as u64,
            block_size: 16 * KB,
            write_rate_limit: None,
        }
    }

    /// Slow HDD compaction profile
    pub fn hdd() -> CompactionProfile {
        CompactionProfile {
            initial_file_size: 256 * MB as u64,
            block_size: 64 * KB,
            write_rate_limit: Some(16 * MB as u64),
        }
    }
}

/// Database configuration
#[derive(Clone)]
pub struct DatabaseConfig {
    /// Max number of open files.
    pub max_open_files: i32,
    /// Memory budget (in MiB) used for setting block cache size, write buffer
    /// size.
    pub memory_budget: Option<usize>,
    /// Compaction profile
    pub compaction: CompactionProfile,
    /// Set number of columns
    pub columns: u32,
    /// Disable WAL if set to `true`
    pub disable_wal: bool,
}

impl DatabaseConfig {
    /// Create new `DatabaseConfig` with default parameters and specified set of
    /// columns. Note that cache sizes must be explicitly set.
    pub fn with_columns(columns: u32) -> Self {
        let mut config = Self::default();
        config.columns = columns;
        config
    }

    pub fn memory_budget(&self) -> usize {
        self.memory_budget.unwrap_or(DB_DEFAULT_MEMORY_BUDGET_MB) * MB
    }

    pub fn memory_budget_per_col(&self) -> usize {
        self.memory_budget() / self.columns as usize
    }

    pub fn memory_budget_mb(&self) -> usize {
        self.memory_budget.unwrap_or(DB_DEFAULT_MEMORY_BUDGET_MB)
    }
}

impl Default for DatabaseConfig {
    fn default() -> DatabaseConfig {
        DatabaseConfig {
            max_open_files: 512,
            memory_budget: None,
            compaction: CompactionProfile::default(),
            columns: 1,
            disable_wal: false,
        }
    }
}

struct DBAndColumns {
    db: DB,
    column_names: Vec<String>,
}

impl DBAndColumns {
    fn get_cf(&self, i: usize) -> &CFHandle {
        self.db
            .cf_handle(&self.column_names[i])
            .expect("the specified column name is correct; qed")
    }

    fn static_property_or_warn(&self, col: usize, prop: &str) -> Option<usize> {
        match self.db.get_property_int_cf(self.get_cf(col), prop) {
            Some(v) => Some(v as usize),
            None => {
                println!("Cannot read expected static property of RocksDb database: {}", prop);
                None
            }
        }
    }
}

impl MallocSizeOf for DBAndColumns {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let mut total = MallocSizeOf::size_of(&self.column_names, ops)
            // we have at least one column always, so we can call property on it
            + self.static_property_or_warn(0, "rocksdb.block-cache-usage").unwrap_or(0);

        for v in 0..self.column_names.len() {
            total += self
                .static_property_or_warn(
                    v,
                    "rocksdb.estimate-table-readers-mem",
                )
                .unwrap_or(0);
            total += self
                .static_property_or_warn(v, "rocksdb.cur-size-all-mem-tables")
                .unwrap_or(0);
        }

        total
    }
}

// get column family configuration from database config.
fn col_config(
    config: &DatabaseConfig, block_opts: &BlockBasedOptions,
) -> io::Result<ColumnFamilyOptions> {
    let mut opts = ColumnFamilyOptions::default();

    opts.set_level_compaction_dynamic_level_bytes(true);
    opts.set_block_based_table_factory(block_opts);
    opts.optimize_level_style_compaction(config.memory_budget_per_col() as i32);
    opts.set_target_file_size_base(config.compaction.initial_file_size);
    opts.set_write_buffer_size(config.memory_budget_per_col() as u64 / 2);
    opts.set_block_cache_size_mb(config.memory_budget_mb() as u64 / 3);

    Ok(opts)
}

unsafe impl Send for Database {}
unsafe impl Sync for Database {}
/// Key-Value database.
#[derive(MallocSizeOfDerive)]
pub struct Database {
    db: RwLock<Option<DBAndColumns>>,
    #[ignore_malloc_size_of = "insignificant"]
    config: DatabaseConfig,
    path: String,
    #[ignore_malloc_size_of = "insignificant"]
    write_opts: WriteOptions,
    #[ignore_malloc_size_of = "insignificant"]
    read_opts: ReadOptions,
    #[ignore_malloc_size_of = "insignificant"]
    block_opts: BlockBasedOptions,
    // Dirty values added with `write_buffered`. Cleaned on `flush`.
    overlay: RwLock<Vec<HashMap<DBKey, KeyState>>>,
    // Values currently being flushed. Cleared when `flush` completes.
    flushing: RwLock<Vec<HashMap<DBKey, KeyState>>>,
    // Prevents concurrent flushes.
    // Value indicates if a flush is in progress.
    flushing_lock: Mutex<bool>,
}

// Compatible hack for KeyValueDB
impl ParityMallocSizeOf for Database {
    fn size_of(&self, _ops: &mut ParityMallocSizeOfOps) -> usize { 0 }
}

#[inline]
fn check_for_corruption<T, P: AsRef<Path>>(
    path: P, res: result::Result<T, DBError>,
) -> io::Result<T> {
    if let Err(ref s) = res {
        if is_corrupted(s) {
            warn!(
                "DB corrupted: {}. Repair will be triggered on next restart",
                s
            );
            let _ = fs::File::create(
                path.as_ref().join(Database::CORRUPTION_FILE_NAME),
            );
        }
    }

    res.map_err(other_io_err)
}

fn is_corrupted(err: &DBError) -> bool {
    err.starts_with("Corruption:")
        || err.starts_with(
            "Invalid argument: You have to open all column families",
        )
}

/// Generate the options for RocksDB, based on the given `DatabaseConfig`.
fn generate_options(config: &DatabaseConfig) -> DBOptions {
    let mut opts = DBOptions::default();

    //TODO: rate_limiter_bytes_per_sec={} was removed

    opts.set_use_fsync(false);
    opts.create_if_missing(true);
    opts.set_max_open_files(config.max_open_files);
    opts.set_bytes_per_sync(1 * MB as u64);
    opts.set_keep_log_file_num(1);
    opts.increase_parallelism(cmp::max(1, num_cpus::get() as i32 / 2));
    opts.enable_statistics(true);

    opts
}

impl Database {
    const CORRUPTION_FILE_NAME: &'static str = "CORRUPTED";

    /// Open database with default settings.
    pub fn open_default(path: &str) -> io::Result<Database> {
        Database::open(&DatabaseConfig::default(), path)
    }

    /// Open database file. Creates if it does not exist.
    pub fn open(config: &DatabaseConfig, path: &str) -> io::Result<Database> {
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_block_size(config.compaction.block_size);
        // Set cache size as recommended by
        // https://github.com/facebook/rocksdb/wiki/Setup-Options-and-Basic-Tuning#block-cache-size
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        block_opts.set_bloom_filter(10, true);

        let opts = generate_options(config);

        // attempt database repair if it has been previously marked as corrupted
        let db_corrupted = Path::new(path).join(Database::CORRUPTION_FILE_NAME);
        if db_corrupted.exists() {
            warn!(
                "DB has been previously marked as corrupted, attempting repair"
            );
            DB::repair(opts.clone(), path).map_err(other_io_err)?;
            fs::remove_file(db_corrupted)?;
        }

        let columns = config.columns as usize;
        if columns == 0 {
            return Err(other_io_err("columns number cannot be 0"));
        }

        let mut cf_options = Vec::with_capacity(columns);
        let column_names: Vec<_> =
            (0..columns).map(|c| format!("col{}", c)).collect();
        let cfnames: Vec<&str> =
            column_names.iter().map(|n| n as &str).collect();

        for i in 0..config.columns {
            cf_options
                .push((cfnames[i as usize], col_config(&config, &block_opts)?));
        }

        let mut write_opts = WriteOptions::new();
        write_opts.disable_wal(config.disable_wal);
        let mut read_opts = ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);
        read_opts.set_verify_checksums(false);

        let db = match DB::open_cf(opts.clone(), path, cf_options.clone()) {
            Ok(db) => {
                for name in &cfnames {
                    let _ = db.cf_handle(name).expect(
                        "rocksdb opens a cf_handle for each cfname; qed",
                    );
                }
                Ok(db)
            }
            Err(_) => {
                // retry and create CFs
                match DB::open_cf(
                    opts.clone(),
                    path,
                    Vec::<(&str, ColumnFamilyOptions)>::new(),
                ) {
                    Ok(mut db) => {
                        for cfd in &cf_options {
                            db.create_cf(cfd.clone()).map_err(other_io_err)?;
                        }
                        Ok(db)
                    }
                    err => err,
                }
            }
        };

        let db = match db {
            Ok(db) => db,
            Err(ref s) if is_corrupted(s) => {
                warn!("DB corrupted: {}, attempting repair", s);
                DB::repair(opts.clone(), path).map_err(other_io_err)?;
                let db = DB::open_cf(opts, path, cf_options)
                    .map_err(other_io_err)?;
                for name in cfnames {
                    let _ = db.cf_handle(name).expect(
                        "rocksdb opens a cf_handle for each cfname; qed",
                    );
                }
                db
            }
            Err(s) => return Err(other_io_err(s)),
        };
        let num_cols = column_names.len();
        Ok(Database {
            db: RwLock::new(Some(DBAndColumns { db, column_names })),
            config: config.clone(),
            overlay: RwLock::new(
                (0..=num_cols).map(|_| HashMap::new()).collect(),
            ),
            flushing: RwLock::new(
                (0..=num_cols).map(|_| HashMap::new()).collect(),
            ),
            flushing_lock: Mutex::new(false),
            path: path.to_owned(),
            read_opts,
            write_opts,
            block_opts,
        })
    }

    /// Helper to create new transaction for this database.
    pub fn transaction(&self) -> DBTransaction { DBTransaction::new() }

    /// Commit transaction to database.
    pub fn write_buffered(&self, tr: DBTransaction) {
        let mut overlay = self.overlay.write();
        let ops = tr.ops;
        for op in ops {
            match op {
                DBOp::Insert { col, key, value } => {
                    overlay[col as usize].insert(key, KeyState::Insert(value));
                }
                DBOp::Delete { col, key } => {
                    overlay[col as usize].insert(key, KeyState::Delete);
                }
            }
        }
    }

    /// Commit buffered changes to database. Must be called under `flush_lock`
    fn write_flushing_with_lock(
        &self, _lock: &mut MutexGuard<'_, bool>,
    ) -> io::Result<()> {
        match *self.db.read() {
            Some(ref cfs) => {
                let batch = WriteBatch::default();
                mem::swap(
                    &mut *self.overlay.write(),
                    &mut *self.flushing.write(),
                );
                {
                    for (c, column) in self.flushing.read().iter().enumerate() {
                        for (key, state) in column.iter() {
                            match *state {
                                KeyState::Delete => {
                                    let cf = cfs.get_cf(c);
                                    batch
                                        .delete_cf(cf, key)
                                        .map_err(other_io_err)?;
                                }
                                KeyState::Insert(ref value) => {
                                    let cf = cfs.get_cf(c);
                                    batch
                                        .put_cf(cf, key, value)
                                        .map_err(other_io_err)?;
                                }
                            }
                        }
                    }
                }

                check_for_corruption(
                    &self.path,
                    cfs.db.write_opt(&batch, &self.write_opts),
                )?;

                for column in self.flushing.write().iter_mut() {
                    column.clear();
                    column.shrink_to_fit();
                }
                Ok(())
            }
            None => Err(other_io_err("Database is closed")),
        }
    }

    /// Commit buffered changes to database.
    pub fn flush(&self) -> io::Result<()> {
        let mut lock = self.flushing_lock.lock();
        // If RocksDB batch allocation fails the thread gets terminated and the
        // lock is released. The value inside the lock is used to detect
        // that.
        if *lock {
            // This can only happen if another flushing thread is terminated
            // unexpectedly.
            return Err(other_io_err(
                "Database write failure. Running low on memory perhaps?",
            ));
        }
        *lock = true;
        let result = self.write_flushing_with_lock(&mut lock);
        *lock = false;
        result
    }

    /// Commit transaction to database.
    pub fn write(&self, tr: DBTransaction) -> io::Result<()> {
        match *self.db.read() {
            Some(ref cfs) => {
                let batch = WriteBatch::default();
                let ops = tr.ops;
                for op in ops {
                    // remove any buffered operation for this key
                    self.overlay.write()[op.col() as usize].remove(op.key());

                    match op {
                        DBOp::Insert { col, key, value } => batch
                            .put_cf(cfs.get_cf(col as usize), &key, &value)
                            .map_err(other_io_err)?,
                        DBOp::Delete { col, key } => batch
                            .delete_cf(cfs.get_cf(col as usize), &key)
                            .map_err(other_io_err)?,
                    }
                }

                check_for_corruption(
                    &self.path,
                    cfs.db.write_opt(&batch, &self.write_opts),
                )
            }
            None => Err(other_io_err("Database is closed")),
        }
    }

    /// Get value by key.
    pub fn get(&self, col: u32, key: &[u8]) -> io::Result<Option<DBValue>> {
        match *self.db.read() {
            Some(ref cfs) => {
                let overlay = &self.overlay.read()[col as usize];
                match overlay.get(key) {
                    Some(&KeyState::Insert(ref value)) => {
                        Ok(Some(value.clone()))
                    }
                    Some(&KeyState::Delete) => Ok(None),
                    None => {
                        let flushing = &self.flushing.read()[col as usize];
                        match flushing.get(key) {
                            Some(&KeyState::Insert(ref value)) => {
                                Ok(Some(value.clone()))
                            }
                            Some(&KeyState::Delete) => Ok(None),
                            None => cfs
                                .db
                                .get_cf_opt(
                                    cfs.get_cf(col as usize),
                                    key,
                                    &self.read_opts,
                                )
                                .map(|r| r.map(|v| v.to_vec()))
                                .map_err(other_io_err),
                        }
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// Close the database
    fn close(&self) {
        *self.db.write() = None;
        self.overlay.write().clear();
        self.flushing.write().clear();
    }

    /// Restore the database from a copy at given path.
    pub fn restore(&self, new_db: &str) -> io::Result<()> {
        self.close();

        // swap is guaranteed to be atomic
        match swap(new_db, &self.path) {
            Ok(_) => {
                // ignore errors
                let _ = fs::remove_dir_all(new_db);
            }
            Err(err) => {
                debug!("DB atomic swap failed: {}", err);
                match swap_nonatomic(new_db, &self.path) {
                    Ok(_) => {
                        // ignore errors
                        let _ = fs::remove_dir_all(new_db);
                    }
                    Err(err) => {
                        warn!("Failed to swap DB directories: {:?}", err);
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "DB restoration failed: could not swap DB directories",
                        ));
                    }
                }
            }
        }

        // reopen the database and steal handles into self
        let db = Self::open(&self.config, &self.path)?;
        *self.db.write() = mem::replace(&mut *db.db.write(), None);
        *self.overlay.write() =
            mem::replace(&mut *db.overlay.write(), Vec::new());
        *self.flushing.write() =
            mem::replace(&mut *db.flushing.write(), Vec::new());
        Ok(())
    }

    /// The number of non-default column families.
    pub fn num_columns(&self) -> u32 {
        self.db
            .read()
            .as_ref()
            .and_then(|db| {
                if db.column_names.is_empty() {
                    None
                } else {
                    Some(db.column_names.len())
                }
            })
            .map(|n| n as u32)
            .unwrap_or(0)
    }

    /// Drop a column family.
    pub fn drop_column(&self) -> io::Result<()> {
        match *self.db.write() {
            Some(DBAndColumns {
                ref mut db,
                ref mut column_names,
            }) => {
                if let Some(name) = column_names.pop() {
                    db.drop_cf(&name).map_err(other_io_err)?;
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Add a column family.
    pub fn add_column(&self) -> io::Result<()> {
        match *self.db.write() {
            Some(DBAndColumns {
                ref mut db,
                ref mut column_names,
            }) => {
                let col = column_names.len() as u32;
                let name = format!("col{}", col);
                db.create_cf((
                    name.as_str(),
                    col_config(&self.config, &self.block_opts)?,
                ))
                .map_err(other_io_err)?;
                column_names.push(name);
                Ok(())
            }
            None => Ok(()),
        }
    }
}

// duplicate declaration of methods here to avoid trait import in certain
// existing cases at time of addition.
impl KeyValueDB for Database {
    fn get(&self, col: u32, key: &[u8]) -> io::Result<Option<DBValue>> {
        Database::get(self, col, key)
    }

    fn get_by_prefix(&self, _col: u32, _prefix: &[u8]) -> Option<Box<[u8]>> {
        unimplemented!()
    }

    fn write_buffered(&self, transaction: DBTransaction) {
        Database::write_buffered(self, transaction)
    }

    fn write(&self, transaction: DBTransaction) -> io::Result<()> {
        Database::write(self, transaction)
    }

    fn flush(&self) -> io::Result<()> { Database::flush(self) }

    fn iter<'a>(
        &'a self, _col: u32,
    ) -> Box<dyn Iterator<Item = KeyValuePair> + 'a> {
        unimplemented!()
    }

    fn iter_from_prefix<'a>(
        &'a self, _col: u32, _prefix: &'a [u8],
    ) -> Box<dyn Iterator<Item = KeyValuePair> + 'a> {
        unimplemented!()
    }

    fn restore(&self, new_db: &str) -> io::Result<()> {
        Database::restore(self, new_db)
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        // write all buffered changes if we can.
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfx_types::H256;
    use std::str::FromStr;
    use tempdir::TempDir;

    fn test_db(config: &DatabaseConfig) {
        let tempdir = TempDir::new("").unwrap();
        let db =
            Database::open(config, tempdir.path().to_str().unwrap()).unwrap();
        let key1 = H256::from_str(
            "02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc",
        )
        .unwrap();
        let key2 = H256::from_str(
            "03c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc",
        )
        .unwrap();
        let key3 = H256::from_str(
            "01c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc",
        )
        .unwrap();

        let mut batch = db.transaction();
        batch.put(0, key1.as_bytes(), b"cat");
        batch.put(0, key2.as_bytes(), b"dog");
        db.write(batch).unwrap();

        assert_eq!(&*db.get(0, key1.as_bytes()).unwrap().unwrap(), b"cat");

        // TODO implement iter
        //        let contents: Vec<_> = db.iter(None).collect();
        //        assert_eq!(contents.len(), 2);
        //        assert_eq!(&*contents[0].0, key1.as_bytes());
        //        assert_eq!(&*contents[0].1, b"cat");
        //        assert_eq!(&*contents[1].0, key2.as_bytes());
        //        assert_eq!(&*contents[1].1, b"dog");

        let mut batch = db.transaction();
        batch.delete(0, key1.as_bytes());
        db.write(batch).unwrap();

        assert!(db.get(0, key1.as_bytes()).unwrap().is_none());

        let mut batch = db.transaction();
        batch.put(0, key1.as_bytes(), b"cat");
        db.write(batch).unwrap();

        let mut transaction = db.transaction();
        transaction.put(0, key3.as_bytes(), b"elephant");
        transaction.delete(0, key1.as_bytes());
        db.write(transaction).unwrap();
        assert!(db.get(0, key1.as_bytes()).unwrap().is_none());
        assert_eq!(&*db.get(0, key3.as_bytes()).unwrap().unwrap(), b"elephant");

        // TODO Implement get_by_prefix
        //        assert_eq!(
        //            &*db.get_by_prefix(None, key3.as_bytes()).unwrap(),
        //            b"elephant"
        //        );
        //        assert_eq!(&*db.get_by_prefix(None, key2.as_bytes()).unwrap(),
        // b"dog");

        let mut transaction = db.transaction();
        transaction.put(0, key1.as_bytes(), b"horse");
        transaction.delete(0, key3.as_bytes());
        db.write_buffered(transaction);
        assert!(db.get(0, key3.as_bytes()).unwrap().is_none());
        assert_eq!(&*db.get(0, key1.as_bytes()).unwrap().unwrap(), b"horse");

        db.flush().unwrap();
        assert!(db.get(0, key3.as_bytes()).unwrap().is_none());
        assert_eq!(&*db.get(0, key1.as_bytes()).unwrap().unwrap(), b"horse");
    }

    #[test]
    fn kvdb() {
        let tempdir = TempDir::new("").unwrap();
        let _ =
            Database::open_default(tempdir.path().to_str().unwrap()).unwrap();
        test_db(&DatabaseConfig::default());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn df_to_rotational() {
        use std::path::PathBuf;
        // Example df output.
        let example_df = vec![
            70, 105, 108, 101, 115, 121, 115, 116, 101, 109, 32, 32, 32, 32,
            32, 49, 75, 45, 98, 108, 111, 99, 107, 115, 32, 32, 32, 32, 32, 85,
            115, 101, 100, 32, 65, 118, 97, 105, 108, 97, 98, 108, 101, 32, 85,
            115, 101, 37, 32, 77, 111, 117, 110, 116, 101, 100, 32, 111, 110,
            10, 47, 100, 101, 118, 47, 115, 100, 97, 49, 32, 32, 32, 32, 32,
            32, 32, 54, 49, 52, 48, 57, 51, 48, 48, 32, 51, 56, 56, 50, 50, 50,
            51, 54, 32, 32, 49, 57, 52, 52, 52, 54, 49, 54, 32, 32, 54, 55, 37,
            32, 47, 10,
        ];
        let expected_output =
            Some(PathBuf::from("/sys/block/sda/queue/rotational"));
        assert_eq!(rotational_from_df_output(example_df), expected_output);
    }

    #[test]
    fn add_columns() {
        let config = DatabaseConfig::default();
        let config_5 = DatabaseConfig::with_columns(5);

        let tempdir = TempDir::new("").unwrap();

        // open empty, add 5.
        {
            let db = Database::open(&config, tempdir.path().to_str().unwrap())
                .unwrap();
            assert_eq!(db.num_columns(), 1);

            for i in 0..4 {
                db.add_column().unwrap();
                assert_eq!(db.num_columns(), i + 2);
            }
        }

        // reopen as 5.
        {
            let db =
                Database::open(&config_5, tempdir.path().to_str().unwrap())
                    .unwrap();
            assert_eq!(db.num_columns(), 5);
        }
    }

    #[test]
    fn drop_columns() {
        let config = DatabaseConfig::default();
        let config_5 = DatabaseConfig::with_columns(5);

        let tempdir = TempDir::new("").unwrap();

        // open 5, remove all.
        {
            let db =
                Database::open(&config_5, tempdir.path().to_str().unwrap())
                    .unwrap();
            assert_eq!(db.num_columns(), 5);

            for i in (0..5).rev() {
                db.drop_column().unwrap();
                assert_eq!(db.num_columns(), i);
            }
        }

        // reopen as 0.
        {
            let db = Database::open(&config, tempdir.path().to_str().unwrap())
                .unwrap();
            assert_eq!(db.num_columns(), 1);
        }
    }

    #[test]
    fn write_clears_buffered_ops() {
        let tempdir = TempDir::new("").unwrap();
        let config = DatabaseConfig::default();
        let db =
            Database::open(&config, tempdir.path().to_str().unwrap()).unwrap();

        let mut batch = db.transaction();
        batch.put(0, b"foo", b"bar");
        db.write_buffered(batch);

        let mut batch = db.transaction();
        batch.put(0, b"foo", b"baz");
        db.write(batch).unwrap();

        assert_eq!(db.get(0, b"foo").unwrap().unwrap(), b"baz");
    }

    #[test]
    fn test_memory_property() {
        let tempdir = TempDir::new("").unwrap();
        let db = Database::open(
            &DatabaseConfig::default(),
            tempdir.path().to_str().unwrap(),
        )
        .unwrap();
        let key1 = H256::from_str(
            "02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc",
        )
        .unwrap();
        let mut tx = db.transaction();
        tx.put(0, key1.as_bytes(), b"123");
        db.write(tx).unwrap();
        db.flush().unwrap();
        let db_locked = db.db.read();
        let db_and_col = db_locked.as_ref().unwrap();
        assert!(db_and_col
            .static_property_or_warn(0, "rocksdb.block-cache-usage")
            .is_some());
        assert!(db_and_col
            .static_property_or_warn(0, "rocksdb.estimate-table-readers-mem",)
            .is_some());
        assert!(db_and_col
            .static_property_or_warn(0, "rocksdb.cur-size-all-mem-tables")
            .is_some());
        assert!(db_and_col
            .static_property_or_warn(0, "rocksdb.fake-property")
            .is_none());
    }
}
