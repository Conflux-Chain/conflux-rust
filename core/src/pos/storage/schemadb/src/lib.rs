// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

//! This library implements a schematized DB on top of [RocksDB](https://rocksdb.org/). It makes
//! sure all data passed in and out are structured according to predefined
//! schemas and prevents access to raw keys and values. This library also
//! enforces a set of Diem specific DB options, like custom comparators and
//! schema-to-column-family mapping.
//!
//! It requires that different kinds of key-value pairs be stored in separate
//! column families.  To use this library to store a kind of key-value pairs,
//! the user needs to use the [`define_schema!`] macro to define the schema
//! name, the types of key and value, and name of the column family.

mod metrics;
#[macro_use]
pub mod schema;

use crate::{
    metrics::{
        DIEM_SCHEMADB_BATCH_COMMIT_BYTES,
        DIEM_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS, DIEM_SCHEMADB_DELETES,
        DIEM_SCHEMADB_GET_BYTES, DIEM_SCHEMADB_GET_LATENCY_SECONDS,
        DIEM_SCHEMADB_ITER_BYTES, DIEM_SCHEMADB_ITER_LATENCY_SECONDS,
        DIEM_SCHEMADB_PUT_BYTES,
    },
    schema::{KeyCodec, Schema, SeekKeyCodec, ValueCodec},
};
use anyhow::{ensure, format_err, Result};
use diem_logger::prelude::*;
use rocksdb::Writable;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    iter::Iterator,
    marker::PhantomData,
    path::Path,
};

/// Type alias to `rocksdb::ReadOptions`. See [`rocksdb doc`](https://github.com/pingcap/rust-rocksdb/blob/master/src/rocksdb_options.rs)
pub type ReadOptions = rocksdb::ReadOptions;

/// Type alias to `rocksdb::Options`.
pub type Options = rocksdb::DBOptions;

/// Type alias to improve readability.
pub type ColumnFamilyName = &'static str;

/// Name for the `default` column family that's always open by RocksDB. We use
/// it to store [`LedgerInfo`](../types/ledger_info/struct.LedgerInfo.html).
pub const DEFAULT_CF_NAME: ColumnFamilyName = "default";

#[derive(Debug)]
enum WriteOp {
    Value(Vec<u8>),
    Deletion,
}

/// `SchemaBatch` holds a collection of updates that can be applied to a DB
/// atomically. The updates will be applied in the order in which they are added
/// to the `SchemaBatch`.
#[derive(Debug, Default)]
pub struct SchemaBatch {
    rows: HashMap<ColumnFamilyName, BTreeMap<Vec<u8>, WriteOp>>,
}

impl SchemaBatch {
    /// Creates an empty batch.
    pub fn new() -> Self { Self::default() }

    /// Adds an insert/update operation to the batch.
    pub fn put<S: Schema>(
        &mut self, key: &S::Key, value: &S::Value,
    ) -> Result<()> {
        let key = <S::Key as KeyCodec<S>>::encode_key(key)?;
        let value = <S::Value as ValueCodec<S>>::encode_value(value)?;
        self.rows
            .entry(S::COLUMN_FAMILY_NAME)
            .or_insert_with(BTreeMap::new)
            .insert(key, WriteOp::Value(value));

        Ok(())
    }

    /// Adds a delete operation to the batch.
    pub fn delete<S: Schema>(&mut self, key: &S::Key) -> Result<()> {
        let key = <S::Key as KeyCodec<S>>::encode_key(key)?;
        self.rows
            .entry(S::COLUMN_FAMILY_NAME)
            .or_insert_with(BTreeMap::new)
            .insert(key, WriteOp::Deletion);

        Ok(())
    }
}

pub enum ScanDirection {
    Forward,
    Backward,
}

/// DB Iterator parameterized on [`Schema`] that seeks with [`Schema::Key`] and
/// yields [`Schema::Key`] and [`Schema::Value`]
pub struct SchemaIterator<'a, S> {
    db_iter: rocksdb::DBIterator<&'a rocksdb::DB>,
    direction: ScanDirection,
    phantom: PhantomData<S>,
}

impl<'a, S> SchemaIterator<'a, S>
where S: Schema
{
    fn new(
        db_iter: rocksdb::DBIterator<&'a rocksdb::DB>, direction: ScanDirection,
    ) -> Self {
        SchemaIterator {
            db_iter,
            direction,
            phantom: PhantomData,
        }
    }

    /// Seeks to the first key.
    pub fn seek_to_first(&mut self) {
        self.db_iter.seek(rocksdb::SeekKey::Start).unwrap();
    }

    /// Seeks to the last key.
    pub fn seek_to_last(&mut self) {
        self.db_iter.seek(rocksdb::SeekKey::End).unwrap();
    }

    /// Seeks to the first key whose binary representation is equal to or
    /// greater than that of the `seek_key`.
    pub fn seek<SK>(&mut self, seek_key: &SK) -> Result<()>
    where SK: SeekKeyCodec<S> {
        let key = <SK as SeekKeyCodec<S>>::encode_seek_key(seek_key)?;
        self.db_iter.seek(rocksdb::SeekKey::Key(&key)).unwrap();
        Ok(())
    }

    /// Seeks to the last key whose binary representation is less than or equal
    /// to that of the `seek_key`.
    ///
    /// See example in [`RocksDB doc`](https://github.com/facebook/rocksdb/wiki/SeekForPrev).
    pub fn seek_for_prev<SK>(&mut self, seek_key: &SK) -> Result<()>
    where SK: SeekKeyCodec<S> {
        let key = <SK as SeekKeyCodec<S>>::encode_seek_key(seek_key)?;
        self.db_iter
            .seek_for_prev(rocksdb::SeekKey::Key(&key))
            .unwrap();
        Ok(())
    }

    fn next_impl(&mut self) -> Result<Option<(S::Key, S::Value)>> {
        let _timer = DIEM_SCHEMADB_ITER_LATENCY_SECONDS
            .with_label_values(&[S::COLUMN_FAMILY_NAME])
            .start_timer();

        if !self.db_iter.valid().unwrap() {
            return Ok(None);
        }

        let raw_key = self.db_iter.key();
        let raw_value = self.db_iter.value();
        DIEM_SCHEMADB_ITER_BYTES
            .with_label_values(&[S::COLUMN_FAMILY_NAME])
            .observe((raw_key.len() + raw_value.len()) as f64);

        let key = <S::Key as KeyCodec<S>>::decode_key(raw_key)?;
        let value = <S::Value as ValueCodec<S>>::decode_value(raw_value)?;

        match self.direction {
            ScanDirection::Forward => self.db_iter.next().unwrap(),
            ScanDirection::Backward => self.db_iter.prev().unwrap(),
        };

        Ok(Some((key, value)))
    }
}

impl<'a, S> Iterator for SchemaIterator<'a, S>
where S: Schema
{
    type Item = Result<(S::Key, S::Value)>;

    fn next(&mut self) -> Option<Self::Item> { self.next_impl().transpose() }
}

/// All the RocksDB methods return `std::result::Result<T, String>`. Since our
/// methods return `anyhow::Result<T>`, manual conversion is needed.
fn convert_rocksdb_err(msg: String) -> anyhow::Error {
    format_err!("RocksDB internal error: {}.", msg)
}

/// This DB is a schematized RocksDB wrapper where all data passed in and out
/// are typed according to [`Schema`]s.
#[derive(Debug)]
pub struct DB {
    name: &'static str, // for logging
    inner: rocksdb::DB,
}

impl DB {
    /// Create db with all the column families provided if it doesn't exist at
    /// `path`; Otherwise, try to open it with all the column families.
    pub fn open(
        path: impl AsRef<Path>, name: &'static str,
        column_families: Vec<ColumnFamilyName>, db_opts: Options,
    ) -> Result<Self> {
        {
            let cfs_set: HashSet<_> = column_families.iter().collect();
            ensure!(
                cfs_set.contains(&DEFAULT_CF_NAME),
                "No \"default\" column family name is provided.",
            );
            ensure!(
                cfs_set.len() == column_families.len(),
                "Duplicate column family name found.",
            );
        }

        let db = DB::open_cf(db_opts, path, name, column_families)?;
        Ok(db)
    }

    /// Open db in readonly mode
    /// Note that this still assumes there's only one process that opens the
    /// same DB. See `open_as_secondary`
    pub fn open_readonly(
        path: impl AsRef<Path>, name: &'static str,
        column_families: Vec<ColumnFamilyName>, db_opts: Options,
    ) -> Result<Self> {
        DB::open_cf_readonly(db_opts, path, name, column_families)
    }

    fn open_cf(
        db_opts: Options, path: impl AsRef<Path>, name: &'static str,
        column_families: Vec<ColumnFamilyName>,
    ) -> Result<DB> {
        let inner = rocksdb::DB::open_cf(
            db_opts,
            path.as_ref().to_str().ok_or_else(|| {
                format_err!(
                    "Path {:?} can not be converted to string.",
                    path.as_ref()
                )
            })?,
            column_families
                .iter()
                .map(|cf_name| {
                    let cf_opts = rocksdb::ColumnFamilyOptions::default();
                    rocksdb::rocksdb_options::ColumnFamilyDescriptor::new(
                        *cf_name, cf_opts,
                    )
                })
                .collect(),
        )
        .map_err(convert_rocksdb_err)?;
        Ok(Self::log_construct(name, inner))
    }

    fn open_cf_readonly(
        opts: Options, path: impl AsRef<Path>, name: &'static str,
        column_families: Vec<ColumnFamilyName>,
    ) -> Result<DB> {
        let error_if_log_file_exists = false;
        let inner = rocksdb::DB::open_cf_for_read_only(
            opts,
            path.as_ref().to_str().ok_or_else(|| {
                format_err!(
                    "Path {:?} can not be converted to string.",
                    path.as_ref()
                )
            })?,
            column_families
                .iter()
                .map(|cf_name| {
                    let cf_opts = rocksdb::ColumnFamilyOptions::default();
                    rocksdb::rocksdb_options::ColumnFamilyDescriptor::new(
                        *cf_name, cf_opts,
                    )
                })
                .collect(),
            error_if_log_file_exists,
        )
        .map_err(convert_rocksdb_err)?;

        Ok(Self::log_construct(name, inner))
    }

    fn log_construct(name: &'static str, inner: rocksdb::DB) -> DB {
        diem_info!(rocksdb_name = name, "Opened RocksDB.");
        DB { name, inner }
    }

    /// Reads single record by key.
    pub fn get<S: Schema>(
        &self, schema_key: &S::Key,
    ) -> Result<Option<S::Value>> {
        let _timer = DIEM_SCHEMADB_GET_LATENCY_SECONDS
            .with_label_values(&[S::COLUMN_FAMILY_NAME])
            .start_timer();

        let k = <S::Key as KeyCodec<S>>::encode_key(&schema_key)?;
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        let result = self
            .inner
            .get_cf(cf_handle, &k)
            .map_err(convert_rocksdb_err)?;
        DIEM_SCHEMADB_GET_BYTES
            .with_label_values(&[S::COLUMN_FAMILY_NAME])
            .observe(result.as_ref().map_or(0.0, |v| v.len() as f64));

        result
            .map(|raw_value| {
                <S::Value as ValueCodec<S>>::decode_value(&raw_value)
            })
            .transpose()
    }

    /// Writes single record.
    pub fn put<S: Schema>(&self, key: &S::Key, value: &S::Value) -> Result<()> {
        // Not necessary to use a batch, but we'd like a central place to bump
        // counters. Used in tests only anyway.
        let mut batch = SchemaBatch::new();
        batch.put::<S>(key, value)?;
        self.write_schemas(batch, false)
    }

    /// Delete all keys in range [begin, end).
    ///
    /// `SK` has to be an explicit type parameter since
    /// <https://github.com/rust-lang/rust/issues/44721>
    pub fn range_delete<S, SK>(&self, begin: &SK, end: &SK) -> Result<()>
    where
        S: Schema,
        SK: SeekKeyCodec<S>,
    {
        let raw_begin = begin.encode_seek_key()?;
        let raw_end = end.encode_seek_key()?;
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        self.inner
            .delete_range_cf(&cf_handle, &raw_begin, &raw_end)
            .map_err(convert_rocksdb_err)
    }

    fn iter_with_direction<S: Schema>(
        &self, opts: ReadOptions, direction: ScanDirection,
    ) -> Result<SchemaIterator<S>> {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        Ok(SchemaIterator::new(
            self.inner.iter_cf_opt(cf_handle, opts),
            direction,
        ))
    }

    /// Returns a forward [`SchemaIterator`] on a certain schema.
    pub fn iter<S: Schema>(
        &self, opts: ReadOptions,
    ) -> Result<SchemaIterator<S>> {
        self.iter_with_direction::<S>(opts, ScanDirection::Forward)
    }

    /// Returns a backward [`SchemaIterator`] on a certain schema.
    pub fn rev_iter<S: Schema>(
        &self, opts: ReadOptions,
    ) -> Result<SchemaIterator<S>> {
        self.iter_with_direction::<S>(opts, ScanDirection::Backward)
    }

    /// Writes a group of records wrapped in a [`SchemaBatch`].
    pub fn write_schemas(
        &self, batch: SchemaBatch, fast_write: bool,
    ) -> Result<()> {
        let _timer = DIEM_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS
            .with_label_values(&[self.name])
            .start_timer();

        let db_batch = rocksdb::WriteBatch::default();
        for (cf_name, rows) in &batch.rows {
            let cf_handle = self.get_cf_handle(cf_name)?;
            for (key, write_op) in rows {
                match write_op {
                    WriteOp::Value(value) => {
                        db_batch.put_cf(cf_handle, key, value).unwrap()
                    }
                    WriteOp::Deletion => {
                        db_batch.delete_cf(cf_handle, key).unwrap()
                    }
                }
            }
        }
        let serialized_size = db_batch.data_size();

        let write_options = if fast_write {
            fast_write_options()
        } else {
            default_write_options()
        };
        self.inner
            .write_opt(&db_batch, &write_options)
            .map_err(convert_rocksdb_err)?;

        // Bump counters only after DB write succeeds.
        for (cf_name, rows) in &batch.rows {
            for (key, write_op) in rows {
                match write_op {
                    WriteOp::Value(value) => {
                        DIEM_SCHEMADB_PUT_BYTES
                            .with_label_values(&[cf_name])
                            .observe((key.len() + value.len()) as f64);
                    }
                    WriteOp::Deletion => {
                        DIEM_SCHEMADB_DELETES
                            .with_label_values(&[cf_name])
                            .inc();
                    }
                }
            }
        }
        DIEM_SCHEMADB_BATCH_COMMIT_BYTES
            .with_label_values(&[self.name])
            .observe(serialized_size as f64);

        Ok(())
    }

    fn get_cf_handle(&self, cf_name: &str) -> Result<&rocksdb::CFHandle> {
        self.inner.cf_handle(cf_name).ok_or_else(|| {
            format_err!(
                "DB::cf_handle not found for column family name: {}",
                cf_name
            )
        })
    }

    /// Flushes all memtable data. This is only used for testing
    /// `get_approximate_sizes_cf` in unit tests.
    pub fn flush_all(&self, sync: bool) -> Result<()> {
        for cf_name in &self.inner.cf_names() {
            let cf_handle = self.get_cf_handle(cf_name)?;
            self.inner
                .flush_cf(cf_handle, sync)
                .map_err(convert_rocksdb_err)?;
        }
        Ok(())
    }

    pub fn get_property(
        &self, cf_name: &str, property_name: &str,
    ) -> Result<u64> {
        self.inner
            .get_property_int_cf(self.get_cf_handle(&cf_name)?, property_name)
            .ok_or_else(|| {
                format_err!(
                    "Unable to get property \"{}\" of  column family \"{}\".",
                    property_name,
                    cf_name,
                )
            })
    }
}

/// For now we always use synchronous writes. This makes sure that once the
/// operation returns `Ok(())` the data is persisted even if the machine
/// crashes. In the future we might consider selectively turning this off for
/// some non-critical writes to improve performance.
fn default_write_options() -> rocksdb::WriteOptions {
    let mut opts = rocksdb::WriteOptions::default();
    opts.set_sync(true);
    opts
}

fn fast_write_options() -> rocksdb::WriteOptions {
    let mut opts = rocksdb::WriteOptions::default();
    opts.set_sync(false);
    // opts.disable_wal(true);
    opts
}
