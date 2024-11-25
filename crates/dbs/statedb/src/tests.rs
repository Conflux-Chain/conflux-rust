// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::StateDbGeneric;
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_storage::{
    utils::access_mode, Error, MptKeyValue, Result, StorageStateTrait,
};
use parking_lot::Mutex;
use primitives::{EpochId, StorageKey, StorageKeyWithSpace, MERKLE_NULL_NODE};
use std::collections::HashMap;

type StorageValue = Box<[u8]>;
type RawStorage = HashMap<Vec<u8>, StorageValue>;

struct MockStorage {
    pub contents: RawStorage,
    num_reads: Mutex<u64>,
    num_writes: u64,
}

impl MockStorage {
    #[allow(unused)]
    fn empty() -> Self {
        MockStorage {
            contents: Default::default(),
            num_reads: Mutex::new(0),
            num_writes: 0,
        }
    }

    fn with_contents(contents: RawStorage) -> Self {
        MockStorage {
            contents,
            num_reads: Mutex::new(0),
            num_writes: 0,
        }
    }

    #[allow(unused)]
    pub fn get_num_reads(&self) -> u64 { *self.num_reads.lock() }

    #[allow(unused)]
    pub fn get_num_writes(&self) -> u64 { self.num_writes }
}

#[allow(unused)]
impl StorageStateTrait for MockStorage {
    fn commit(&mut self, epoch: EpochId) -> Result<StateRootWithAuxInfo> {
        self.compute_state_root()
    }

    fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        Ok(StateRootWithAuxInfo::genesis(&MERKLE_NULL_NODE))
    }

    fn delete(&mut self, access_key: StorageKeyWithSpace) -> Result<()> {
        self.num_writes += 1;
        let key = access_key.to_key_bytes();
        self.contents.remove(&key);
        Ok(())
    }

    fn delete_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        let prefix = access_key_prefix.to_key_bytes();

        let keys_to_delete: Vec<_> = self
            .contents
            .keys()
            .filter(|k| k.starts_with(&prefix[..]))
            .cloned()
            .collect();

        let mut deleted_kvs = vec![];

        for k in keys_to_delete {
            *self.num_reads.get_mut() += 1;
            let v = self.contents.get(&k).unwrap();
            deleted_kvs.push((k.clone(), v.clone()));

            self.num_writes += 1;
            self.contents.remove(&k);
        }

        Ok(Some(deleted_kvs))
    }

    fn delete_test_only(
        &mut self, access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        unimplemented!()
    }

    fn get(
        &self, access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        *self.num_reads.lock() += 1;
        let key = access_key.to_key_bytes();
        Ok(self.contents.get(&key).cloned())
    }

    fn get_state_root(&self) -> Result<StateRootWithAuxInfo> {
        Err(Error::Msg("No state root".to_owned()).into())
    }

    fn set(
        &mut self, access_key: StorageKeyWithSpace, value: Box<[u8]>,
    ) -> Result<()> {
        self.num_writes += 1;
        let key = access_key.to_key_bytes();
        self.contents.insert(key, value);
        Ok(())
    }

    fn read_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        let prefix = access_key_prefix.to_key_bytes();

        let keys: Vec<_> = self
            .contents
            .keys()
            .filter(|k| k.starts_with(&prefix[..]))
            .cloned()
            .collect();

        let mut kvs = vec![];

        for k in keys {
            *self.num_reads.get_mut() += 1;
            let v = self.contents.get(&k).unwrap();
            kvs.push((k.clone(), v.clone()));
        }

        Ok(Some(kvs))
    }
}

type StateDbTest = StateDbGeneric;

// convert `key` to storage interface format
fn storage_key(key: &'static [u8]) -> StorageKeyWithSpace {
    StorageKey::AccountKey(key).with_native_space()
}

// convert `key` to raw storage format
fn key(key: &'static [u8]) -> Vec<u8> { storage_key(key).to_key_bytes() }

// convert `value` to raw storage format
fn value(value: &'static [u8]) -> StorageValue { value.into() }

fn init_state_db() -> StateDbTest {
    let mut contents = RawStorage::new();
    contents.insert(key(b"00"), value(b"v0"));
    contents.insert(key(b"01"), value(b"v0"));
    contents.insert(key(b"11"), value(b"v0"));
    contents.insert(key(b"22"), value(b"v0"));

    let storage = MockStorage::with_contents(contents);
    StateDbTest::new(Box::new(storage))
}

#[allow(unused)]
fn print_raw(raw: &RawStorage) {
    let mut keys: Vec<_> = raw.keys().collect();
    keys.sort();

    for k in keys {
        let v = &raw[k];
        println!(
            "k = {:?}; v = {:?}",
            std::str::from_utf8(k).unwrap(),
            std::str::from_utf8(v).unwrap()
        );
    }
}

#[test]
fn test_basic() {
    let mut state_db = init_state_db();

    // (11, v0) --> (11, v1)
    state_db
        .set_raw(storage_key(b"11"), value(b"v1"), None)
        .unwrap();

    // delete (22, v0)
    state_db.delete(storage_key(b"22"), None).unwrap();

    // delete (00, v0) and (01, v0)
    state_db
        .delete_all::<access_mode::Write>(storage_key(b"0"), None)
        .unwrap();

    state_db.commit(MERKLE_NULL_NODE, None).unwrap();
    // FIXME(lpl): Enable tests.
    // let storage = (state_db.get_storage_mut() as &dyn
    // Any).downcast_ref::<MockStorage>().unwrap(); let contents =
    // &storage.contents;
    //
    // // we expect only one value after commit
    // let expected: HashMap<_, _> =
    //     [(key(b"11"), value(b"v1"))].iter().cloned().collect();
    //
    // assert_eq!(*contents, expected);
    //
    // // we need to read all values touched
    // assert_eq!(storage.get_num_reads(), 4);
    //
    // // we need to write all values modified or removed
    // assert_eq!(storage.get_num_writes(), 4);
}
