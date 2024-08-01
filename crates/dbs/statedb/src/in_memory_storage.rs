use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
};

use cfx_internal_common::StateRootWithAuxInfo;
use cfx_storage::{state::StateTrait as StorageTrait, ErrorKind, Result};
use cfx_types::H256;
use primitives::StorageKeyWithSpace;
use tiny_keccak::{Hasher, Keccak};

thread_local! {
    static HASHMAP: RefCell<HashMap<primitives::EpochId, BTreeMap<Vec<u8>, Box<[u8]>>>> = RefCell::new(HashMap::new());
}

#[derive(Default)]
pub struct InmemoryStorage {
    inner: BTreeMap<Vec<u8>, Box<[u8]>>,
    cached_state_root: Option<StateRootWithAuxInfo>,
}

impl InmemoryStorage {
    pub fn from_epoch_id(epoch_id: &primitives::EpochId) -> Option<Self> {
        HASHMAP.with_borrow(|x| {
            Some(Self {
                inner: x.get(&epoch_id)?.clone(),
                cached_state_root: None,
            })
        })
    }
}

impl StorageTrait for InmemoryStorage {
    fn get(
        &self, access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        Ok(self.inner.get(&access_key.to_key_bytes()).cloned())
    }

    fn set(
        &mut self, access_key: StorageKeyWithSpace, value: Box<[u8]>,
    ) -> Result<()> {
        self.inner.insert(access_key.to_key_bytes(), value);
        Ok(())
    }

    fn delete(&mut self, access_key: StorageKeyWithSpace) -> Result<()> {
        self.inner.remove(&access_key.to_key_bytes());
        Ok(())
    }

    fn delete_test_only(
        &mut self, access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        Ok(self.inner.remove(&access_key.to_key_bytes()))
    }

    fn delete_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<cfx_storage::MptKeyValue>>> {
        let prefix = access_key_prefix.to_key_bytes();
        let deleted = extract_prefix(&mut self.inner, &prefix);
        if deleted.is_empty() {
            return Ok(None);
        }

        Ok(Some(deleted.into_iter().collect()))
    }

    fn read_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<cfx_storage::MptKeyValue>>> {
        let kvs = read_prefix(&self.inner, &access_key_prefix.to_key_bytes());
        Ok(if kvs.is_empty() { None } else { Some(kvs) })
    }

    fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        if let Some(ref state_root) = self.cached_state_root {
            return Ok(state_root.clone());
        }

        let mut x = Keccak::v256();
        self.inner.iter().for_each(|(k, v)| {
            x.update(&k);
            x.update(&v);
        });

        let mut output = [0u8; 32];
        x.finalize(&mut output);

        let state_root = StateRootWithAuxInfo::genesis(&H256(output));
        self.cached_state_root = Some(state_root.clone());
        Ok(state_root)
    }

    fn get_state_root(&self) -> Result<StateRootWithAuxInfo> {
        self.cached_state_root
            .clone()
            .ok_or(ErrorKind::Msg("No state root".to_owned()).into())
    }

    fn commit(
        &mut self, epoch: primitives::EpochId,
    ) -> Result<StateRootWithAuxInfo> {
        let root = self.compute_state_root()?;
        HASHMAP.with_borrow_mut(|x| x.insert(epoch, self.inner.clone()));
        Ok(root)
    }
}

fn read_prefix<'a, K: AsRef<[u8]> + Ord + Clone, V: Clone>(
    map: &'a BTreeMap<K, V>, prefix: &'a K,
) -> Vec<(K, V)> {
    map.range(prefix..)
        .take_while(|(k, _)| k.as_ref().starts_with(prefix.as_ref()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn extract_prefix<K: AsRef<[u8]> + Ord + Clone, V>(
    map: &mut BTreeMap<K, V>, prefix: &K,
) -> BTreeMap<K, V> {
    let mut extracted = BTreeMap::new();

    let keys_to_remove: Vec<K> = map
        .range(prefix..)
        .take_while(|(k, _)| k.as_ref().starts_with(prefix.as_ref()))
        .map(|(k, _)| k.clone())
        .collect();

    for key in keys_to_remove {
        if let Some(value) = map.remove(&key) {
            extracted.insert(key, value);
        }
    }

    extracted
}
