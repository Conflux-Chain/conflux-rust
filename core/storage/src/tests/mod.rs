// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod snapshot;
pub use snapshot::FakeSnapshotMptDb;

#[cfg(test)]
mod proofs;
#[cfg(test)]
mod sharded_iter_merger;
#[cfg(test)]
mod state;

#[cfg(test)]
const TEST_NUMBER_OF_KEYS: usize = 100000;

#[derive(Default)]
pub struct FakeDbForStateTest {}

// Compatible hack for KeyValueDB
impl MallocSizeOf for FakeDbForStateTest {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl KeyValueDB for FakeDbForStateTest {
    fn get(&self, _col: u32, _key: &[u8]) -> std::io::Result<Option<DBValue>> {
        Ok(None)
    }

    fn get_by_prefix(&self, _col: u32, _prefix: &[u8]) -> Option<Box<[u8]>> {
        unreachable!()
    }

    /// No-op
    fn write_buffered(&self, _transaction: DBTransaction) {}

    /// No-op
    fn flush(&self) -> std::io::Result<()> { Ok(()) }

    fn iter<'a>(
        &'a self, _col: u32,
    ) -> Box<dyn Iterator<Item = (Box<[u8]>, Box<[u8]>)>> {
        unreachable!()
    }

    fn iter_from_prefix<'a>(
        &'a self, _col: u32, _prefix: &'a [u8],
    ) -> Box<dyn Iterator<Item = (Box<[u8]>, Box<[u8]>)>> {
        unreachable!()
    }

    fn restore(&self, _new_db: &str) -> std::io::Result<()> { unreachable!() }
}

#[cfg(any(test, feature = "testonly_code"))]
pub struct FakeStateManager {
    data_dir: String,
    state_manager: Option<Arc<StateManager>>,
}

#[cfg(any(test, feature = "testonly_code"))]
impl FakeStateManager {
    fn new(
        conflux_data_dir: String, snapshot_epoch_count: u32,
    ) -> Result<Self> {
        // Use a random directory to prevent conflicts in concurrently running
        // tests.
        let unit_test_data_dir =
            conflux_data_dir + &random::<u64>().to_string();
        fs::create_dir_all(unit_test_data_dir.as_str())?;
        let mut storage_conf = StorageConfiguration::new_default(
            &unit_test_data_dir,
            snapshot_epoch_count,
        );
        storage_conf.delta_mpts_cache_size = 20_000_000;
        storage_conf.delta_mpts_cache_start_size = 1_000_000;
        storage_conf.delta_mpts_node_map_vec_size = 20_000_000;
        storage_conf.delta_mpts_slab_idle_size = 200_000;

        Ok(FakeStateManager {
            data_dir: unit_test_data_dir,
            state_manager: Some(Arc::new(StateManager::new(storage_conf)?)),
        })
    }
}

#[cfg(any(test, feature = "testonly_code"))]
impl Drop for FakeStateManager {
    fn drop(&mut self) {
        self.state_manager.take();
        fs::remove_dir_all(self.data_dir.as_str()).ok();
        let maybe_parent_dir = Path::new(self.data_dir.as_str()).parent();
        if let Some(parent_dir) = maybe_parent_dir {
            fs::remove_dir(parent_dir).ok();
        }
    }
}

#[cfg(any(test, feature = "testonly_code"))]
impl Deref for FakeStateManager {
    type Target = Arc<StateManager>;

    fn deref(&self) -> &Self::Target { self.state_manager.as_ref().unwrap() }
}

#[cfg(any(test, feature = "testonly_code"))]
impl DerefMut for FakeStateManager {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state_manager.as_mut().unwrap()
    }
}

#[cfg(any(test, feature = "testonly_code"))]
pub fn new_state_manager_for_unit_test_with_snapshot_epoch_count(
    snapshot_epoch_count: u32,
) -> FakeStateManager {
    const WITH_LOGGER: bool = false;
    if WITH_LOGGER {
        log4rs::init_config(
            log4rs::config::Config::builder()
                .appender(
                    log4rs::config::Appender::builder().build(
                        "stdout",
                        Box::new(
                            log4rs::append::console::ConsoleAppender::builder()
                                .build(),
                        ),
                    ),
                )
                .build(
                    log4rs::config::Root::builder()
                        .appender("stdout")
                        .build(log::LevelFilter::Debug),
                )
                .unwrap(),
        )
        .ok();
    }

    FakeStateManager::new(
        "./conflux_unit_test_data_dir".to_string(),
        snapshot_epoch_count,
    )
    .unwrap()
}

#[cfg(any(test, feature = "testonly_code"))]
pub fn new_state_manager_for_unit_test() -> FakeStateManager {
    let snapshot_epoch_count = 10;
    new_state_manager_for_unit_test_with_snapshot_epoch_count(
        snapshot_epoch_count,
    )
}

#[derive(Default)]
pub struct DumpedMptKvIterator {
    pub kv: Vec<MptKeyValue>,
}

pub struct DumpedMptKvFallibleIterator {
    pub kv: Vec<MptKeyValue>,
    pub index: usize,
}

impl DumpedMptKvIterator {
    pub fn iterate<'a, DeltaMptDumper: KVInserter<MptKeyValue>>(
        &self, dumper: &mut DeltaMptDumper,
    ) -> Result<()> {
        let mut sorted_kv = self.kv.clone();
        sorted_kv.sort();
        for kv_item in sorted_kv {
            dumper.push(kv_item)?;
        }
        Ok(())
    }
}

impl KVInserter<MptKeyValue> for DumpedMptKvIterator {
    fn push(&mut self, v: MptKeyValue) -> Result<()> {
        let (mpt_key, value) = v;
        let snapshot_key =
            StorageKey::from_delta_mpt_key(&mpt_key).to_key_bytes();

        self.kv.push((snapshot_key, value));
        Ok(())
    }
}

impl FallibleIterator for DumpedMptKvFallibleIterator {
    type Error = Error;
    type Item = MptKeyValue;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        let result = Ok(self.kv.get(self.index).cloned());
        self.index += 1;
        result
    }
}

#[cfg(test)]
fn generate_keys(number_of_keys: usize) -> Vec<Vec<u8>> {
    let mut rng = get_rng_for_test();

    let mut keys_num: Vec<u64> = Default::default();

    for _i in 0..number_of_keys {
        keys_num.push(rng.gen());
    }

    keys_num.sort();

    let mut keys = vec![];
    let mut last_key = keys_num[0];
    for key in &keys_num[1..number_of_keys] {
        if *key != last_key {
            keys.push(Vec::from(
                &unsafe { std::mem::transmute::<u64, [u8; 8]>(key.clone()) }[..],
            ));
        }
        last_key = *key;
    }

    keys.shuffle(&mut rng);
    keys
}

#[cfg(test)]
fn generate_account_keys(number_of_keys: usize) -> Vec<Vec<u8>> {
    let mut rng = get_rng_for_test();
    (0..number_of_keys)
        .map(|_| rng.gen::<[u8; 20]>().to_vec())
        .collect()
}

#[cfg(test)]
fn get_rng_for_test() -> ChaChaRng { ChaChaRng::from_seed([123; 32]) }

// Kept for debugging.
#[allow(dead_code)]
pub fn print_mpt_key(key: &[u8]) {
    print!("key = (");
    for char in key {
        print!(
            "{}, {}, ",
            CompressedPathRaw::first_nibble(*char),
            CompressedPathRaw::second_nibble(*char)
        );
    }
    println!(")");
}

#[cfg(any(test, feature = "testonly_code"))]
use crate::{impls::state_manager::StateManager, StorageConfiguration};
use crate::{
    impls::{
        errors::*,
        merkle_patricia_trie::{CompressedPathRaw, MptKeyValue},
    },
    KVInserter,
};
use fallible_iterator::FallibleIterator;
use kvdb::{DBTransaction, DBValue, KeyValueDB};
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps};
use primitives::StorageKey;
#[cfg(any(test, feature = "testonly_code"))]
use rand::random;
#[cfg(test)]
use rand::{seq::SliceRandom, Rng, SeedableRng};
#[cfg(test)]
use rand_chacha::ChaChaRng;
#[cfg(any(test, feature = "testonly_code"))]
use std::{
    fs,
    ops::{Deref, DerefMut},
    path::Path,
    sync::Arc,
};
