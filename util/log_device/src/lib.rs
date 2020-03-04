// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use byteorder::{ByteOrder, LittleEndian};
use db::SystemDB;
use kvdb::DBTransaction;
use parking_lot::Mutex;
use rlp::Rlp;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Error, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
};

// database columns for rocksdb
/// Column for miscellaneous items
const COL_DB: Option<u32> = Some(0);
/// Number of columns in DB
const NUM_COLUMNS: Option<u32> = Some(1);

const DB_KEY_LOG_DEVICE_NUM: &[u8] = b"log_device_num";

const NUM_OF_STRIPES_PER_SEGMENT: u64 = 2000;
const META_DATA_DB_DIR: &str = "meta_db";
const LOG_DEVICE_DIR_PREFIX: &str = "log_device_";
const SEGMENT_FILE_NAME_PREFIX: &str = "segment_";

/// Here is the folder structure of log devices.
/// path_dir/meta_db/
///         /log_device_0/segment_0
///                      /segment_1
///                      /...
///         /log_device_1/segment_0
///                      /segment_1
///                      /...
///         /...

/// There is an independent file for each segment in a log.
/// This is to facilitate log trimming in garbage collection.

#[derive(Clone, Copy, Debug, Default, RlpDecodable, RlpEncodable)]
pub struct StripeReference {
    /// Segment id of the stripe.
    segment_id: u64,
    /// Offset in bytes of the stripe in the segment.
    offset: u64,
}

#[derive(Clone, Copy, Debug, Default, RlpDecodable, RlpEncodable)]
pub struct StripeInfo {
    /// The reference to the stripe.
    stripe_ref: StripeReference,
    /// The id of the stripe in the segment.
    stripe_id: u64,
}

pub struct LogDeviceManager {
    path_dir: PathBuf,
    db: Arc<SystemDB>,
    devices: Mutex<Vec<Arc<LogDevice>>>,
}

impl LogDeviceManager {
    pub fn new(path_dir: PathBuf) -> Self {
        let mut db_dir_path = path_dir.clone();
        db_dir_path.push(META_DATA_DB_DIR);
        let db_config = db::db_config(
            &db_dir_path,
            None,
            db::DatabaseCompactionProfile::default(),
            NUM_COLUMNS.clone(),
            false, /* disable_wal */
        );

        let db = db::open_database(db_dir_path.to_str().unwrap(), &db_config)
            .unwrap();

        let mut log_device_manager = LogDeviceManager {
            path_dir,
            db,
            devices: Mutex::new(Vec::new()),
        };
        log_device_manager.initialize();
        log_device_manager
    }

    fn initialize(&mut self) {
        let device_num = self.get_device_num_from_db();
        let mut devices = self.devices.lock();
        for i in 0..device_num {
            let mut log_device_filename = String::from(LOG_DEVICE_DIR_PREFIX);
            log_device_filename.push_str(i.to_string().as_str());
            let mut device_path_dir = self.path_dir.clone();
            device_path_dir.push(log_device_filename.as_str());
            let log_device = LogDevice::new(
                device_path_dir,
                i,
                self.db.clone(),
                true, /* open */
            );
            devices.push(Arc::new(log_device));
        }
    }

    fn get_device_num_from_db(&self) -> usize {
        let res = self
            .db
            .key_value()
            .get(COL_DB, DB_KEY_LOG_DEVICE_NUM)
            .expect("Low level database error.");
        let device_num = match res {
            Some(value) => LittleEndian::read_u64(&value) as usize,
            None => 0,
        };

        device_num
    }

    fn set_device_num_to_db(&self, device_num: usize) {
        let mut tx = DBTransaction::new();
        let mut value = [0; 8];
        LittleEndian::write_u64(&mut value[0..8], device_num as u64);
        tx.put(COL_DB, DB_KEY_LOG_DEVICE_NUM, &value);
        self.db.key_value().write(tx).expect("DB write failed.");
    }

    pub fn get_device_num(&self) -> usize { self.devices.lock().len() }

    pub fn get_device(&self, device_id: usize) -> Option<Arc<LogDevice>> {
        Some(self.devices.lock().get(device_id)?.clone())
    }

    pub fn create_new_device(&self) -> usize {
        let new_device_id = self.get_device_num();
        let mut log_device_filename = String::from(LOG_DEVICE_DIR_PREFIX);
        log_device_filename.push_str(new_device_id.to_string().as_str());
        let mut device_path_dir = self.path_dir.clone();
        device_path_dir.push(log_device_filename.as_str());
        let log_device = LogDevice::new(
            device_path_dir,
            new_device_id,
            self.db.clone(),
            false, /* open */
        );
        self.devices.lock().push(Arc::new(log_device));
        let new_device_num = new_device_id + 1;
        self.set_device_num_to_db(new_device_num);
        self.db.key_value().flush().expect("DB flush failed.");
        new_device_id
    }
}

pub struct LogDevice {
    device_id: usize,
    tail_db_key: String,
    head_db_key: String,
    db: Arc<SystemDB>,
    inner: Mutex<LogDeviceInner>,
}

impl LogDevice {
    pub fn new(
        path_dir: PathBuf, device_id: usize, db: Arc<SystemDB>, open: bool,
    ) -> Self {
        let mut log_device = LogDevice {
            device_id,
            tail_db_key: String::default(),
            head_db_key: String::default(),
            db: db.clone(),
            inner: Mutex::new(LogDeviceInner::new(path_dir)),
        };

        log_device.tail_db_key = log_device.get_tail_key();
        log_device.head_db_key = log_device.get_head_key();
        let (head, tail) = if open {
            let tail = log_device
                .get_stripe_info_from_db(log_device.tail_db_key.as_bytes())
                .unwrap();
            let head = log_device
                .get_stripe_info_from_db(log_device.head_db_key.as_bytes())
                .unwrap();
            (head, tail)
        } else {
            let tail = StripeInfo {
                stripe_ref: StripeReference {
                    segment_id: 0,
                    offset: 0,
                },
                stripe_id: 0,
            };

            let head = tail;
            log_device.set_stripe_info_to_db(
                log_device.tail_db_key.as_bytes(),
                &tail,
            );
            log_device.set_stripe_info_to_db(
                log_device.head_db_key.as_bytes(),
                &head,
            );
            db.key_value().flush().expect("DB flush failed.");
            (head, tail)
        };

        log_device.inner.lock().initialize(head, tail);
        log_device
    }

    fn get_tail_key(&self) -> String {
        let mut tail_key = String::from(LOG_DEVICE_DIR_PREFIX);
        tail_key.push_str(self.device_id.to_string().as_str());
        tail_key.push_str("_tail");
        tail_key
    }

    fn get_head_key(&self) -> String {
        let mut head_key = String::from(LOG_DEVICE_DIR_PREFIX);
        head_key.push_str(self.device_id.to_string().as_str());
        head_key.push_str("_head");
        head_key
    }

    fn get_stripe_info_from_db(&self, key: &[u8]) -> Option<StripeInfo> {
        let res = self
            .db
            .key_value()
            .get(COL_DB, key)
            .expect("Low level database error.");
        match res {
            Some(value) => {
                let rlp = Rlp::new(&value);
                let stripe_info: StripeInfo = rlp.as_val().expect("rlp error");
                Some(stripe_info)
            }
            None => None,
        }
    }

    fn set_stripe_info_to_db(&self, key: &[u8], stripe_info: &StripeInfo) {
        let value = rlp::encode(stripe_info);
        let mut tx = DBTransaction::new();
        tx.put(COL_DB, key, value.as_slice());
        self.db.key_value().write(tx).expect("DB write failed.");
    }

    pub fn append_stripe(&self, stripe: &[u8]) -> Result<StripeInfo, Error> {
        let (appended_stripe, tail) =
            self.inner.lock().append_stripe(stripe)?;
        self.set_stripe_info_to_db(self.tail_db_key.as_bytes(), &tail);
        self.db.key_value().flush()?;
        Ok(appended_stripe)
    }

    pub fn get_stripe(
        &self, stripe_ref: &StripeReference,
    ) -> Result<Vec<u8>, Error> {
        self.inner.lock().get_stripe(stripe_ref)
    }

    pub fn trim(&self, stripe: &StripeInfo) {
        let mut inner = self.inner.lock();
        let new_head = inner.check_trim(stripe.stripe_ref.segment_id);
        if new_head.is_some() {
            let new_head = new_head.unwrap();
            self.set_stripe_info_to_db(self.head_db_key.as_bytes(), &new_head);
            self.db.key_value().flush().expect("DB flush failed.");
            inner.trim(&new_head);
        }
    }

    pub fn segment_to_file_name(segment_id: u64) -> String {
        let mut filename = String::from(SEGMENT_FILE_NAME_PREFIX);
        filename.push_str(segment_id.to_string().as_str());
        filename
    }
}

struct LogDeviceInner {
    /// The info of the next to-be-appended stripe in this log.
    tail: StripeInfo,
    /// The info of the head stripe of the log.
    /// Only segment information matters in head stripe info.
    head: StripeInfo,
    /// The directory where the log device files locate.
    path_dir: PathBuf,
    /// The cache maintaining the opened segment files.
    /// FIXME: make it lru.
    file_cache: HashMap<u64, File>,
}

impl LogDeviceInner {
    pub fn new(path_dir: PathBuf) -> Self {
        LogDeviceInner {
            tail: StripeInfo::default(),
            head: StripeInfo::default(),
            path_dir,
            file_cache: HashMap::new(),
        }
    }

    fn initialize(&mut self, head: StripeInfo, tail: StripeInfo) {
        self.head = head;
        self.tail = tail;

        // Open and check the file holding the tail.
        let segment_path =
            self.segment_to_path(self.tail.stripe_ref.segment_id);
        let create = if segment_path.exists() {
            false
        } else {
            assert_eq!(self.tail.stripe_ref.segment_id, 0);
            assert_eq!(self.tail.stripe_ref.offset, 0);
            assert_eq!(self.tail.stripe_id, 0);
            std::fs::create_dir_all(&self.path_dir)
                .expect("Failed to create log_device dir.");
            true
        };
        let mut segment_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create)
            .open(&segment_path)
            .expect("Failed to open segment file.");
        let offset = segment_file
            .seek(SeekFrom::Start(self.tail.stripe_ref.offset))
            .expect("Failed to seek segment file.");
        assert_eq!(offset, self.tail.stripe_ref.offset);
        self.file_cache
            .insert(self.tail.stripe_ref.segment_id, segment_file);
    }

    fn segment_to_path(&self, segment: u64) -> PathBuf {
        let segment_filename = LogDevice::segment_to_file_name(segment);
        let mut segment_path = self.path_dir.clone();
        segment_path.push(segment_filename.as_str());
        segment_path
    }

    pub fn append_stripe(
        &mut self, stripe: &[u8],
    ) -> Result<(StripeInfo, StripeInfo), Error> {
        // Check size.
        let payload_size = LittleEndian::read_u32(&stripe[0..4]) as usize;
        assert_eq!(payload_size + 4, stripe.len(), "Incorrect payload size.");

        if self.tail.stripe_id == NUM_OF_STRIPES_PER_SEGMENT {
            // The current segment is full. Need to create new segment.
            self.tail.stripe_ref.segment_id += 1;
            self.tail.stripe_ref.offset = 0;
            self.tail.stripe_id = 0;

            // Create new segment file.
            let segment_path =
                self.segment_to_path(self.tail.stripe_ref.segment_id);
            let segment_file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&segment_path)?;
            self.file_cache
                .insert(self.tail.stripe_ref.segment_id, segment_file);
        }

        // Append stripe to segment file.
        let segment_file = self
            .file_cache
            .get_mut(&self.tail.stripe_ref.segment_id)
            .unwrap();
        let write_size = segment_file.write(stripe)?;
        // FIXME: for better error handling.
        assert_eq!(write_size, stripe.len());
        let offset = self.tail.stripe_ref.offset + write_size as u64;
        assert_eq!(segment_file.seek(SeekFrom::End(0)).unwrap(), offset);
        segment_file.flush()?;

        let appended_stripe = self.tail;
        // Update tail information.
        self.tail.stripe_id += 1;
        self.tail.stripe_ref.offset = offset;
        Ok((appended_stripe, self.tail))
    }

    pub fn get_stripe(
        &mut self, stripe_ref: &StripeReference,
    ) -> Result<Vec<u8>, Error> {
        if !self.file_cache.contains_key(&stripe_ref.segment_id) {
            // The segment file hasn't been accessed. Open and cache it.
            let segment_path = self.segment_to_path(stripe_ref.segment_id);
            let segment_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&segment_path)?;
            self.file_cache.insert(stripe_ref.segment_id, segment_file);
        }

        let segment_file =
            self.file_cache.get_mut(&stripe_ref.segment_id).unwrap();
        let offset = segment_file.seek(SeekFrom::Start(stripe_ref.offset))?;
        assert_eq!(offset, stripe_ref.offset);
        let mut stripe: Vec<u8> = Vec::new();
        stripe.resize(4, 0);
        let read_size = segment_file.read(&mut stripe[0..4])?;
        assert_eq!(read_size, 4);
        let payload_size = LittleEndian::read_u32(&stripe[0..4]) as usize;
        if payload_size != 0 {
            stripe.resize(payload_size + 4, 0);
            let read_size =
                segment_file.read(&mut stripe[4..4 + payload_size])?;
            assert_eq!(read_size, payload_size);
        }
        Ok(stripe)
    }

    pub fn check_trim(&self, segment_id: u64) -> Option<StripeInfo> {
        if segment_id >= self.head.stripe_ref.segment_id
            && segment_id <= self.tail.stripe_ref.segment_id
        {
            Some(StripeInfo {
                stripe_ref: StripeReference {
                    segment_id,
                    offset: 0,
                },
                stripe_id: 0,
            })
        } else {
            None
        }
    }

    pub fn trim(&mut self, new_head: &StripeInfo) {
        let old_head = self.head;
        self.head = *new_head;

        for segment in
            old_head.stripe_ref.segment_id..self.head.stripe_ref.segment_id
        {
            self.file_cache.remove(&segment);
            let segment_path = self.segment_to_path(segment);
            if segment_path.exists() {
                std::fs::remove_file(&segment_path).ok();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LogDevice, LogDeviceManager, LOG_DEVICE_DIR_PREFIX,
        NUM_OF_STRIPES_PER_SEGMENT,
    };
    use crate::{StripeInfo, StripeReference};
    use byteorder::{ByteOrder, LittleEndian};
    use rand::Rng;
    use std::{path::PathBuf, sync::Arc};

    fn gen_random_and_append(
        log_device: Arc<LogDevice>, stripes: &mut Vec<Vec<u8>>,
        stripe_refs: &mut Vec<StripeReference>, start: usize, end: usize,
    )
    {
        for i in start..end {
            let mut stripe: Vec<u8> = Vec::new();
            let stripe_size = rand::thread_rng().gen_range(4, 1024 * 64);
            stripe.resize(stripe_size, i as u8);
            let payload_size = stripe_size - 4;
            LittleEndian::write_u32(&mut stripe[0..4], payload_size as u32);
            let stripe_info = log_device.append_stripe(&stripe).unwrap();
            stripes.push(stripe);
            stripe_refs.push(stripe_info.stripe_ref);
        }
    }

    fn read_and_check(
        log_device: Arc<LogDevice>, stripes: &Vec<Vec<u8>>,
        stripe_refs: &Vec<StripeReference>, start: usize, end: usize,
    )
    {
        for i in start..end {
            let stripe = &stripes[i];
            let stripe_ref = &stripe_refs[i];
            let read_stripe = log_device
                .get_stripe(stripe_ref)
                .expect("Failed to read stripe");
            let matching = stripe
                .iter()
                .zip(read_stripe.iter())
                .filter(|&(a, b)| a == b)
                .count();
            assert_eq!(matching, stripe.len());
            assert_eq!(matching, read_stripe.len());
        }
    }

    fn create_and_append(
        stripes: &mut Vec<Vec<u8>>, stripe_refs: &mut Vec<StripeReference>,
    ) {
        let path_dir = String::from("./ldm_open");
        let path_dir = PathBuf::from(path_dir);
        std::fs::remove_dir_all(&path_dir).ok();
        std::fs::create_dir_all(&path_dir).ok();
        let log_device_manager = LogDeviceManager::new(path_dir.clone());
        assert_eq!(log_device_manager.get_device_num(), 0);
        let device_id = log_device_manager.create_new_device();
        assert_eq!(log_device_manager.get_device_num(), 1);
        assert_eq!(log_device_manager.get_device_num_from_db(), 1);
        let log_device = log_device_manager.get_device(device_id).unwrap();

        gen_random_and_append(log_device.clone(), stripes, stripe_refs, 0, 10);
        read_and_check(log_device.clone(), stripes, stripe_refs, 0, 10);
    }

    fn open_and_append_and_read(
        stripes: &mut Vec<Vec<u8>>, stripe_refs: &mut Vec<StripeReference>,
    ) {
        let path_dir = String::from("./ldm_open");
        let path_dir = PathBuf::from(path_dir);
        let log_device_manager = LogDeviceManager::new(path_dir.clone());
        assert_eq!(log_device_manager.get_device_num(), 1);
        let log_device = log_device_manager.get_device(0).unwrap();

        gen_random_and_append(log_device.clone(), stripes, stripe_refs, 10, 20);
        read_and_check(log_device.clone(), stripes, stripe_refs, 0, 20);
        std::fs::remove_dir_all(&path_dir).ok();
    }

    #[test]
    fn test_open_log_device() {
        let mut stripes = Vec::new();
        let mut stripe_refs = Vec::new();

        create_and_append(&mut stripes, &mut stripe_refs);
        open_and_append_and_read(&mut stripes, &mut stripe_refs);
    }

    #[test]
    fn test_append_log_device() {
        let path_dir = String::from("./ldm_append");
        let path_dir = PathBuf::from(path_dir);
        std::fs::remove_dir_all(&path_dir).ok();
        std::fs::create_dir_all(&path_dir).ok();
        let log_device_manager = LogDeviceManager::new(path_dir.clone());
        assert_eq!(log_device_manager.get_device_num(), 0);
        let device_id = log_device_manager.create_new_device();
        assert_eq!(log_device_manager.get_device_num(), 1);
        let log_device = log_device_manager.get_device(device_id).unwrap();
        let mut stripes = Vec::new();
        let mut stripe_refs = Vec::new();

        gen_random_and_append(
            log_device.clone(),
            &mut stripes,
            &mut stripe_refs,
            0,
            10,
        );
        read_and_check(log_device.clone(), &stripes, &stripe_refs, 0, 10);
        std::fs::remove_dir_all(&path_dir).ok();
    }

    #[test]
    fn test_trim_log_device() {
        let path_dir = String::from("./ldm_trim");
        let path_dir = PathBuf::from(path_dir);
        std::fs::remove_dir_all(&path_dir).ok();
        std::fs::create_dir_all(&path_dir).ok();
        let log_device_manager = LogDeviceManager::new(path_dir.clone());
        assert_eq!(log_device_manager.get_device_num(), 0);
        let device_id = log_device_manager.create_new_device();
        assert_eq!(log_device_manager.get_device_num(), 1);
        let log_device = log_device_manager.get_device(device_id).unwrap();
        let mut stripes = Vec::new();
        let mut stripe_refs = Vec::new();

        gen_random_and_append(
            log_device.clone(),
            &mut stripes,
            &mut stripe_refs,
            0,
            4 * NUM_OF_STRIPES_PER_SEGMENT as usize,
        );

        let mut log_device_path_dir = path_dir.clone();
        let mut log_device_dir = String::from(LOG_DEVICE_DIR_PREFIX);
        log_device_dir.push_str("0");
        log_device_path_dir.push(log_device_dir.as_str());

        let mut segment_0_path = log_device_path_dir.clone();
        segment_0_path.push("segment_0");
        let mut segment_1_path = log_device_path_dir.clone();
        segment_1_path.push("segment_1");
        let mut segment_2_path = log_device_path_dir.clone();
        segment_2_path.push("segment_2");
        let mut segment_3_path = log_device_path_dir.clone();
        segment_3_path.push("segment_3");

        assert!(segment_0_path.exists());
        assert!(segment_1_path.exists());
        assert!(segment_2_path.exists());
        assert!(segment_3_path.exists());

        let strip_info = StripeInfo {
            stripe_ref: StripeReference {
                segment_id: 2,
                offset: 0,
            },
            stripe_id: 0,
        };
        log_device.trim(&strip_info);

        assert!(!segment_0_path.exists());
        assert!(!segment_1_path.exists());
        assert!(segment_2_path.exists());
        assert!(segment_3_path.exists());

        read_and_check(
            log_device.clone(),
            &stripes,
            &stripe_refs,
            2 * NUM_OF_STRIPES_PER_SEGMENT as usize,
            4 * NUM_OF_STRIPES_PER_SEGMENT as usize,
        );

        std::fs::remove_dir_all(&path_dir).ok();
    }

    #[test]
    fn test_create_log_device() {
        let path_dir = String::from("./ldm_create");
        let path_dir = PathBuf::from(path_dir);
        std::fs::remove_dir_all(&path_dir).ok();
        std::fs::create_dir_all(&path_dir).ok();
        let log_device_manager = LogDeviceManager::new(path_dir.clone());
        assert_eq!(log_device_manager.get_device_num(), 0);
        assert_eq!(log_device_manager.get_device_num_from_db(), 0);
        log_device_manager.create_new_device();
        assert_eq!(log_device_manager.get_device_num(), 1);
        assert_eq!(log_device_manager.get_device_num_from_db(), 1);
        log_device_manager.create_new_device();
        assert_eq!(log_device_manager.get_device_num(), 2);
        assert_eq!(log_device_manager.get_device_num_from_db(), 2);
        log_device_manager.create_new_device();
        assert_eq!(log_device_manager.get_device_num(), 3);
        assert_eq!(log_device_manager.get_device_num_from_db(), 3);
        log_device_manager.create_new_device();
        assert_eq!(log_device_manager.get_device_num(), 4);
        assert_eq!(log_device_manager.get_device_num_from_db(), 4);

        let mut log_device_path_dir = path_dir.clone();
        let mut log_device_dir = String::from(LOG_DEVICE_DIR_PREFIX);
        log_device_dir.push_str("0");
        log_device_path_dir.push(log_device_dir.as_str());
        let mut segment_0_path = log_device_path_dir.clone();
        segment_0_path.push("segment_0");
        assert!(segment_0_path.exists());

        let mut log_device_path_dir = path_dir.clone();
        let mut log_device_dir = String::from(LOG_DEVICE_DIR_PREFIX);
        log_device_dir.push_str("1");
        log_device_path_dir.push(log_device_dir.as_str());
        let mut segment_0_path = log_device_path_dir.clone();
        segment_0_path.push("segment_0");
        assert!(segment_0_path.exists());

        let mut log_device_path_dir = path_dir.clone();
        let mut log_device_dir = String::from(LOG_DEVICE_DIR_PREFIX);
        log_device_dir.push_str("2");
        log_device_path_dir.push(log_device_dir.as_str());
        let mut segment_0_path = log_device_path_dir.clone();
        segment_0_path.push("segment_0");
        assert!(segment_0_path.exists());

        let mut log_device_path_dir = path_dir.clone();
        let mut log_device_dir = String::from(LOG_DEVICE_DIR_PREFIX);
        log_device_dir.push_str("3");
        log_device_path_dir.push(log_device_dir.as_str());
        let mut segment_0_path = log_device_path_dir.clone();
        segment_0_path.push("segment_0");
        assert!(segment_0_path.exists());

        std::fs::remove_dir_all(&path_dir).ok();
    }
}
