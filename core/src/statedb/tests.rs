// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::StateDbGeneric;
use crate::storage::{
    utils::{access_mode, StaticBool},
    MptKeyValue, NodeMerkleProof, Result, StateProof, StateRootWithAuxInfo,
    StorageStateTrait,
};
use primitives::{EpochId, NodeMerkleTriplet, StorageKey};
use std::{cell::RefCell, collections::HashMap};

type StorageValue = Box<[u8]>;
type RawStorage = HashMap<StorageKey<'static>, StorageValue>;

struct MockStorage {
    contents: RawStorage,
    num_reads: RefCell<u64>,
    num_writes: RefCell<u64>,
}

impl MockStorage {
    #[allow(unused)]
    fn empty() -> Self {
        MockStorage {
            contents: Default::default(),
            num_reads: RefCell::new(0),
            num_writes: RefCell::new(0),
        }
    }

    fn with_contents(contents: RawStorage) -> Self {
        MockStorage {
            contents,
            num_reads: RefCell::new(0),
            num_writes: RefCell::new(0),
        }
    }

    pub fn get_num_reads(&self) -> u64 { self.num_reads.borrow().clone() }

    #[allow(unused)]
    pub fn get_num_writes(&self) -> u64 { self.num_writes.borrow().clone() }
}

#[allow(unused)]
impl StorageStateTrait for MockStorage {
    fn commit(&mut self, epoch: EpochId) -> Result<StateRootWithAuxInfo> {
        // TODO
        unimplemented!()
    }

    fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        // TODO
        unimplemented!()
    }

    fn delete(&mut self, access_key: StorageKey) -> Result<()> {
        // TODO
        unimplemented!()
    }

    fn delete_all<AM: access_mode::AccessMode>(
        &mut self, access_key_prefix: StorageKey,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        // TODO
        unimplemented!()
    }

    fn delete_test_only(
        &mut self, access_key: StorageKey,
    ) -> Result<Option<Box<[u8]>>> {
        unimplemented!()
    }

    fn get(&self, access_key: StorageKey) -> Result<Option<Box<[u8]>>> {
        *self.num_reads.borrow_mut() += 1;
        Ok(self.contents.get(&access_key).cloned())
    }

    fn get_node_merkle_all_versions<WithProof: StaticBool>(
        &self, access_key: StorageKey,
    ) -> Result<(NodeMerkleTriplet, NodeMerkleProof)> {
        unimplemented!()
    }

    fn get_state_root(&self) -> Result<StateRootWithAuxInfo> {
        // TODO
        unimplemented!()
    }

    fn get_with_proof(
        &self, access_key: StorageKey,
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        unimplemented!()
    }

    fn revert(&mut self) { unimplemented!() }

    fn set(&mut self, access_key: StorageKey, value: Box<[u8]>) -> Result<()> {
        // TODO
        unimplemented!()
    }
}

type StateDbTest = StateDbGeneric<MockStorage>;

// TODO(thegaram): StateDb calls StorageKey::from_key_bytes
// so we need to construct a legit storage key
fn storage_key(key: &'static [u8]) -> StorageKey<'static> {
    StorageKey::AccountKey(key)
}

fn storage_value(value: &'static [u8]) -> StorageValue { value.into() }

fn init_state_db() -> StateDbTest {
    let mut contents = HashMap::new();
    contents.insert(storage_key(b"0"), storage_value(b"0-v0"));
    contents.insert(storage_key(b"1"), storage_value(b"1-v0"));
    contents.insert(storage_key(b"2"), storage_value(b"2-v0"));
    contents.insert(storage_key(b"3"), storage_value(b"3-v0"));
    contents.insert(storage_key(b"4"), storage_value(b"4-v0"));

    let storage = MockStorage::with_contents(contents);
    StateDbTest::new(storage)
}

#[test]
fn test_basic() {
    let mut state_db = init_state_db();

    state_db
        .set_raw(storage_key(b"0"), storage_value(b"0-v1"), None)
        .unwrap();

    // use super::StateDbCheckpointMethods;
    // state_db.checkpoint(); // checkpoint #0

    assert_eq!(state_db.get_storage_mut().get_num_reads(), 1);
}
