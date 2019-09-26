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

#[macro_use]
extern crate log;

extern crate fs_swap;
extern crate num_cpus;
extern crate regex;
extern crate rocksdb;

#[cfg(test)]
extern crate cfx_types;

extern crate kvdb;

use std::{cmp, fs, io, result, error};
use std::path::Path;

use rocksdb::{
	DB, WriteBatch, WriteOptions, IteratorMode, DBIterator, Options, Error,
	BlockBasedOptions, Direction, ColumnFamily, ColumnFamilyDescriptor, ReadOptions,
};

use kvdb::{
	DBValue, NumColumns, OpenHandler, TransactionHandler, IterationHandler,
	MigrationHandler, WriteTransaction, ReadTransaction,
};

pub use kvdb::DatabaseWithCache;

#[cfg(target_os = "linux")]
use regex::Regex;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

fn other_io_err<E>(e: E) -> io::Error where E: Into<Box<dyn error::Error + Send + Sync>> {
	io::Error::new(io::ErrorKind::Other, e)
}

const DB_DEFAULT_MEMORY_BUDGET_MB: usize = 128;
const CORRUPTION_FILE_NAME: &'static str = "CORRUPTED";
const CF_HANDLE_PROOF: &'static str = "rocksdb opens a cf_handle for each cfname; qed";


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
	fn default() -> CompactionProfile {
		CompactionProfile::ssd()
	}
}

/// Given output of df command return Linux rotational flag file path.
#[cfg(target_os = "linux")]
pub fn rotational_from_df_output(df_out: Vec<u8>) -> Option<PathBuf> {
	use std::str;
	str::from_utf8(df_out.as_slice())
		.ok()
		// Get the drive name.
		.and_then(|df_str| Regex::new(r"/dev/(sd[:alpha:]{1,2})")
			.ok()
			.and_then(|re| re.captures(df_str))
			.and_then(|captures| captures.get(1)))
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
					if buffer == [48] { return Self::ssd(); }
					// 1 means rotational.
					if buffer == [49] { return Self::hdd(); }
				}
			}
		}
		// Fallback if drive type was not determined.
		Self::default()
	}

	/// Just default for other platforms.
	#[cfg(not(target_os = "linux"))]
	pub fn auto(_db_path: &Path) -> CompactionProfile {
		Self::default()
	}

	/// Default profile suitable for SSD storage
	pub fn ssd() -> CompactionProfile {
		CompactionProfile {
			initial_file_size: 64 * 1024 * 1024,
			block_size: 16 * 1024,
			write_rate_limit: None,
		}
	}

	/// Slow HDD compaction profile
	pub fn hdd() -> CompactionProfile {
		CompactionProfile {
			initial_file_size: 256 * 1024 * 1024,
			block_size: 64 * 1024,
			write_rate_limit: Some(16 * 1024 * 1024),
		}
	}
}

/// Database configuration
#[derive(Clone)]
pub struct DatabaseConfig {
	/// Max number of open files.
	pub max_open_files: i32,
	/// Memory budget (in MiB) used for setting block cache size, write buffer size.
	pub memory_budget: Option<usize>,
	/// Compaction profile
	pub compaction: CompactionProfile,
	/// Set number of columns
	pub columns: Option<u32>,
    /// Disable write-ahead-log
    pub disable_wal: bool,
}

impl DatabaseConfig {
	/// Create new `DatabaseConfig` with default parameters and specified set of columns.
	/// Note that cache sizes must be explicitly set.
	pub fn with_columns(columns: Option<u32>) -> Self {
		let mut config = Self::default();
		config.columns = columns;
		config
	}

	pub fn memory_budget(&self) -> usize {
		self.memory_budget.unwrap_or(DB_DEFAULT_MEMORY_BUDGET_MB) * 1024 * 1024
	}

	pub fn memory_budget_per_col(&self) -> usize {
		self.memory_budget() / self.columns.unwrap_or(1) as usize
	}
}

impl Default for DatabaseConfig {
	fn default() -> DatabaseConfig {
		DatabaseConfig {
			max_open_files: 512,
			memory_budget: None,
			compaction: CompactionProfile::default(),
			columns: None,
			disable_wal: false,
		}
	}
}

pub struct DBAndColumns {
	db: DB,
	cf_names: Vec<String>,
	path: String,
	write_opts: WriteOptions,
	read_opts: ReadOptions,
	block_opts: BlockBasedOptions,
}

unsafe impl Send for DBAndColumns {}
unsafe impl Sync for DBAndColumns {}

// get column family configuration from database config.
fn col_config(config: &DatabaseConfig, block_opts: &BlockBasedOptions) -> io::Result<Options> {
	let mut opts = Options::default();

	// TODO: add to upstream
	// opts.set_parsed_options("level_compaction_dynamic_level_bytes=true").map_err(other_io_err)?;

	opts.set_block_based_table_factory(block_opts);

	// TODO: add to upstream (pin_l0_filter_and_index_blocks_in_cache)
	// opts.set_parsed_options(
	// 	&format!("block_based_table_factory={{{};{}}}",
	// 			 "cache_index_and_filter_blocks=true",
	// 			 "pin_l0_filter_and_index_blocks_in_cache=true")).map_err(other_io_err)?;

	opts.optimize_level_style_compaction(config.memory_budget_per_col());
	opts.set_target_file_size_base(config.compaction.initial_file_size);

	opts.set_compression_per_level(&[]);

	Ok(opts)
}

/// Key-Value database.
pub type Database = DatabaseWithCache<DBAndColumns>;

// TODO: fix upstream to take options as a ref for DB::repair
impl DBAndColumns {

	fn options(config: &DatabaseConfig) -> Options {
		let mut opts = Options::default();

		if let Some(_rate_limit) = config.compaction.write_rate_limit {
			// TODO: add to upstream
			// opts.set_parsed_options(&format!("rate_limiter_bytes_per_sec={}", rate_limit)).map_err(other_io_err)?;
		}
		opts.set_use_fsync(false);
		opts.create_if_missing(true);
		opts.set_max_open_files(config.max_open_files);
		opts.set_keep_log_file_num(1);
		opts.set_bytes_per_sync(1048576);
		opts.set_write_buffer_size(config.memory_budget_per_col() / 2);
		opts.increase_parallelism(cmp::max(1, ::num_cpus::get() as i32 / 2));
		opts.enable_statistics();

		opts
	}
}

impl OpenHandler<DBAndColumns> for DBAndColumns {
	type Config = DatabaseConfig;

	fn open(config: &Self::Config, path: &str) -> io::Result<DBAndColumns> {
		let opts = Self::options(config);
		let mut block_opts = BlockBasedOptions::default();

		{
			block_opts.set_block_size(config.compaction.block_size);
			let cache_size = cmp::max(8 * 1024 * 1024, config.memory_budget() / 3);
			block_opts.set_lru_cache(cache_size);
		}

		// attempt database repair if it has been previously marked as corrupted
		let db_corrupted = Path::new(path).join(CORRUPTION_FILE_NAME);
		if db_corrupted.exists() {
			warn!("DB has been previously marked as corrupted, attempting repair");
			let opts2 = Self::options(config);
			DB::repair(opts2, path).map_err(other_io_err)?;
			fs::remove_file(db_corrupted)?;
		}

		let columns = config.columns.unwrap_or(0) as usize;

		let mut cf_descriptors = Vec::with_capacity(columns);
		let mut cf_options = Vec::with_capacity(columns);
		let cf_names: Vec<_> = (0..columns).map(|c| format!("col{}", c)).collect();
		let cfnames: Vec<&str> = cf_names.iter().map(|n| n as &str).collect();

		for name in &cf_names {
			cf_descriptors.push(ColumnFamilyDescriptor::new(name.clone(), col_config(&config, &block_opts)?));
			// TODO: avoid calling col_config twice (fix upstream)
			cf_options.push(col_config(&config, &block_opts)?);
		}

		let mut write_opts = WriteOptions::default();
		write_opts.disable_wal(config.disable_wal);
		let read_opts = ReadOptions::default();
		// TODO: add to upstream
		// read_opts.set_verify_checksums(false);

		let db = match config.columns {
			Some(_) => {
				match DB::open_cf_descriptors(&opts, path, cf_descriptors) {
					db @ Ok(_) => db,
					Err(_) => {
						// retry and create CFs
						let names: &[&str] = &[];
						match DB::open_cf(&opts, path, names) {
							Ok(db) => {
								for (i, n)in cfnames.iter().enumerate() {
									let _ = db.create_cf(n, &cf_options[i]).map_err(other_io_err)?;
								}
								Ok(db)
							},
							err => err,
						}
					}
				}
			},
			None => DB::open(&opts, path)
		};

		let db = match db {
			Ok(db) => db,
			Err(ref s) if is_corrupted(&s.clone().into_string()) => {
				warn!("DB corrupted: {}, attempting repair", s);
				let opts2 = Self::options(config);
				DB::repair(opts2, path).map_err(other_io_err)?;

				match cfnames.is_empty() {
					true => DB::open(&opts, path).map_err(other_io_err)?,
					false => {
						// TODO: fix upstream to take cf_descriptors as refs
						let cf_descriptors: Vec<_> = cfnames.iter()
							.zip(cf_options)
							.map(|(name, option)| ColumnFamilyDescriptor::new(name.clone(), option))
							.collect();
						let db = DB::open_cf_descriptors(&opts, path, cf_descriptors).map_err(other_io_err)?;
						db
					},
				}
			},
			Err(s) => {
				return Err(other_io_err(s))
			}
		};

		Ok(DBAndColumns{
			db,
			// TODO: avoid clone
			cf_names: cf_names.clone(),
			path: path.to_owned(),
			write_opts,
			read_opts,
			block_opts,
		})
	}
}

impl NumColumns for DatabaseConfig {
	fn num_columns(&self) -> usize {
		(self.columns.unwrap_or_default() + 1) as usize
	}
}

struct RocksDBWriteTransaction<'a> {
	batch: WriteBatch,
	path: &'a str,
	db: &'a DB,
	write_opts: &'a WriteOptions,
	cfs: Vec<ColumnFamily<'a>>,
}

impl<'a> WriteTransaction for RocksDBWriteTransaction<'a> {
	fn put(&mut self, c: usize, key: &[u8], value: &[u8]) -> io::Result<()> {
		if c > 0 {
			self.batch.put_cf(self.cfs[c - 1], key, value).map_err(other_io_err)
		} else {
			self.batch.put(key, value).map_err(other_io_err)
		}
	}

	fn delete(&mut self, c: usize, key: &[u8]) -> io::Result<()> {
		if c > 0 {
			self.batch.delete_cf(self.cfs[c - 1], key).map_err(other_io_err)
		} else {
			self.batch.delete(key).map_err(other_io_err)
		}
	}

	fn commit(self: Box<Self>) -> io::Result<()> {
		let Self { db, path, write_opts, batch, ..} = *self;
		check_for_corruption(
			path,
			db.write_opt(batch, write_opts),
		)
	}
}

struct RocksDBReadTransaction<'a> {
	db: &'a DB,
	read_opts: &'a ReadOptions,
	cfs: Vec<ColumnFamily<'a>>,
}

impl<'a> ReadTransaction for RocksDBReadTransaction<'a> {
	fn get(self: Box<Self>, c: usize, key: &[u8]) -> io::Result<Option<DBValue>> {
		if c > 0 {
			self.db.get_cf_opt(self.cfs[c - 1], key, &self.read_opts)
		} else {
			self.db.get_opt(key, &self.read_opts)
		}
			.map_err(other_io_err)
			.map(|r| r.map(|v| DBValue::from_slice(&v)))
	}
}

impl DBAndColumns {
	fn column_families(&self) -> Vec<ColumnFamily> {
		self.cf_names.iter().map(|name| self.db.cf_handle(&name).expect(CF_HANDLE_PROOF)).collect()
	}
}

impl TransactionHandler for DBAndColumns {
	fn write_transaction<'a>(&'a self) -> Box<dyn WriteTransaction + 'a> {
		Box::new(RocksDBWriteTransaction {
			batch: WriteBatch::default(),
			db: &self.db,
			path: &self.path,
			write_opts: &self.write_opts,
			cfs: self.column_families(),
		})
	}

	fn read_transaction<'a>(&'a self) -> Box<dyn ReadTransaction + 'a> {
		Box::new(RocksDBReadTransaction {
			db: &self.db,
			read_opts: &self.read_opts,
			cfs: self.column_families(),
		})
	}
}

impl<'a> IterationHandler for &'a DBAndColumns {
	type Iterator = DBIterator<'a>;

	fn iter(&self, c: usize) -> Self::Iterator {
		if c > 0 {
			let cfs = self.column_families();
			self.db.iterator_cf_opt(
				cfs[c - 1],
				&self.read_opts,
				IteratorMode::Start,
			).expect("iterator params are valid; qed")
		} else {
			self.db.iterator_opt(IteratorMode::Start, &self.read_opts)
		}
	}

	fn iter_from_prefix(&self, c: usize, prefix: & [u8]) -> Self::Iterator {
		if c > 0 {
			let cfs = self.column_families();
			self.db.iterator_cf_opt(
				cfs[c - 1],
				&self.read_opts,
				IteratorMode::From(prefix, Direction::Forward),
			).expect("iterator params are valid; qed")
		} else {
			self.db.iterator_opt(
				IteratorMode::From(prefix, Direction::Forward),
				&self.read_opts,
			)
		}
	}
}

#[inline]
fn check_for_corruption<T, P: AsRef<Path>>(path: P, res: result::Result<T, Error>) -> io::Result<T> {
	if let Err(ref s) = res {
		if s.clone().into_string().starts_with("Corruption:") {
			warn!("DB corrupted: {}. Repair will be triggered on next restart", s);
			let _ = fs::File::create(path.as_ref().join(CORRUPTION_FILE_NAME));
		}
	}

	res.map_err(other_io_err)
}

fn is_corrupted(s: &str) -> bool {
	s.starts_with("Corruption:") || s.starts_with("Invalid argument: You have to open all column families")
}

impl NumColumns for DBAndColumns {
	fn num_columns(&self) -> usize {
		if self.cf_names.is_empty() { 0 } else { self.cf_names.len() }
	}
}

impl MigrationHandler<DBAndColumns> for DBAndColumns {
	fn drop_column(&mut self) -> io::Result<()> {
		if let Some(col) = self.cf_names.pop() {
			let name = format!("col{}", self.cf_names.len());
			drop(col);
			self.db.drop_cf(&name).map_err(other_io_err)?;
		}
		Ok(())
	}

	fn add_column(&mut self, config: &<DBAndColumns as OpenHandler<DBAndColumns>>::Config) -> io::Result<()> {
		let col = self.cf_names.len() as u32;
		let name = format!("col{}", col);
		let _ = self.db.create_cf(&name, &col_config(config, &self.block_opts)?).map_err(other_io_err)?;
		self.cf_names.push(name);
		Ok(())
	}
}


#[cfg(test)]
mod tests {
	extern crate tempdir;

	use std::str::FromStr;
	use self::tempdir::TempDir;
	use cfx_types::H256;
	use super::*;

	fn test_db(config: &DatabaseConfig) {
		let tempdir = TempDir::new("").unwrap();
		let db = Database::open(config, tempdir.path().to_str().unwrap()).unwrap();
		let key1 = H256::from_str("02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc").unwrap();
		let key2 = H256::from_str("03c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc").unwrap();
		let key3 = H256::from_str("01c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc").unwrap();

		let mut batch = db.transaction();
		batch.put(None, &key1, b"cat");
		batch.put(None, &key2, b"dog");
		db.write(batch).unwrap();

		assert_eq!(&*db.get(None, &key1).unwrap().unwrap(), b"cat");

		let contents: Vec<_> = db.iter(None).collect();
		assert_eq!(contents.len(), 2);
		assert_eq!(&*contents[0].0, &*key1);
		assert_eq!(&*contents[0].1, b"cat");
		assert_eq!(&*contents[1].0, &*key2);
		assert_eq!(&*contents[1].1, b"dog");

		let mut batch = db.transaction();
		batch.delete(None, &key1);
		db.write(batch).unwrap();

		assert!(db.get(None, &key1).unwrap().is_none());

		let mut batch = db.transaction();
		batch.put(None, &key1, b"cat");
		db.write(batch).unwrap();

		let mut transaction = db.transaction();
		transaction.put(None, &key3, b"elephant");
		transaction.delete(None, &key1);
		db.write(transaction).unwrap();
		assert!(db.get(None, &key1).unwrap().is_none());
		assert_eq!(&*db.get(None, &key3).unwrap().unwrap(), b"elephant");

		assert_eq!(&*db.get_by_prefix(None, &key3).unwrap(), b"elephant");
		assert_eq!(&*db.get_by_prefix(None, &key2).unwrap(), b"dog");

		let mut transaction = db.transaction();
		transaction.put(None, &key1, b"horse");
		transaction.delete(None, &key3);
		db.write_buffered(transaction);
		assert!(db.get(None, &key3).unwrap().is_none());
		assert_eq!(&*db.get(None, &key1).unwrap().unwrap(), b"horse");

		db.flush().unwrap();
		assert!(db.get(None, &key3).unwrap().is_none());
		assert_eq!(&*db.get(None, &key1).unwrap().unwrap(), b"horse");
	}

	#[test]
	fn kvdb() {
		let tempdir = TempDir::new("").unwrap();
		let _ = Database::open_default(tempdir.path().to_str().unwrap()).unwrap();
		test_db(&DatabaseConfig::default());
	}

	#[test]
	#[cfg(target_os = "linux")]
	fn df_to_rotational() {
		use std::path::PathBuf;
		// Example df output.
		let example_df = vec![70, 105, 108, 101, 115, 121, 115, 116, 101, 109, 32, 32, 32, 32, 32, 49, 75, 45, 98, 108, 111, 99, 107, 115, 32, 32, 32, 32, 32, 85, 115, 101, 100, 32, 65, 118, 97, 105, 108, 97, 98, 108, 101, 32, 85, 115, 101, 37, 32, 77, 111, 117, 110, 116, 101, 100, 32, 111, 110, 10, 47, 100, 101, 118, 47, 115, 100, 97, 49, 32, 32, 32, 32, 32, 32, 32, 54, 49, 52, 48, 57, 51, 48, 48, 32, 51, 56, 56, 50, 50, 50, 51, 54, 32, 32, 49, 57, 52, 52, 52, 54, 49, 54, 32, 32, 54, 55, 37, 32, 47, 10];
		let expected_output = Some(PathBuf::from("/sys/block/sda/queue/rotational"));
		assert_eq!(rotational_from_df_output(example_df), expected_output);
	}

	#[test]
	fn add_columns() {
		let config = DatabaseConfig::default();
		let config_5 = DatabaseConfig::with_columns(Some(5));

		let tempdir = TempDir::new("").unwrap();

		// open empty, add 5.
		{
			let db = Database::open(&config, tempdir.path().to_str().unwrap()).unwrap();
			assert_eq!(db.num_columns(), 0);

			for i in 0..5 {
				db.add_column().unwrap();
				assert_eq!(db.num_columns(), i + 1);
			}
		}

		// reopen as 5.
		{
			let db = Database::open(&config_5, tempdir.path().to_str().unwrap()).unwrap();
			assert_eq!(db.num_columns(), 5);
		}
	}

	#[test]
	fn drop_columns() {
		let config = DatabaseConfig::default();
		let config_5 = DatabaseConfig::with_columns(Some(5));

		let tempdir = TempDir::new("").unwrap();

		// open 5, remove all.
		{
			let db = Database::open(&config_5, tempdir.path().to_str().unwrap()).unwrap();
			assert_eq!(db.num_columns(), 5);

			for i in (0..5).rev() {
				db.drop_column().unwrap();
				assert_eq!(db.num_columns(), i);
			}
		}

		// reopen as 0.
		{
			let db = Database::open(&config, tempdir.path().to_str().unwrap()).unwrap();
			assert_eq!(db.num_columns(), 0);
		}
	}

	#[test]
	fn write_clears_buffered_ops() {
		let tempdir = TempDir::new("").unwrap();
		let config = DatabaseConfig::default();
		let db = Database::open(&config, tempdir.path().to_str().unwrap()).unwrap();

		let mut batch = db.transaction();
		batch.put(None, b"foo", b"bar");
		db.write_buffered(batch);

		let mut batch = db.transaction();
		batch.put(None, b"foo", b"baz");
		db.write(batch).unwrap();

		assert_eq!(db.get(None, b"foo").unwrap().unwrap().as_ref(), b"baz");
	}
}
