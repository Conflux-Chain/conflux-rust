use std::{
    collections::HashMap,
    hash::Hash,
    ops::{Deref, DerefMut},
};

use cfx_types::U256;
use malloc_size_of_derive::MallocSizeOf;
use treap_map::KeyMngTrait;

use crate::packing_batch::PackingBatch;

use super::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
};

#[derive(Default, Clone, MallocSizeOf)]
pub(crate) struct PackingPoolExtMap<K: Eq + Hash>(HashMap<K, U256>);

impl<K: Eq + Hash> Deref for PackingPoolExtMap<K> {
    type Target = HashMap<K, U256>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<K: Eq + Hash> DerefMut for PackingPoolExtMap<K> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl<TX: PackingPoolTransaction> KeyMngTrait<PackingPoolMap<TX>>
    for PackingPoolExtMap<TX::Sender>
{
    #[inline]
    fn view_update(
        &mut self, key: &TX::Sender, value: Option<&PackingBatch<TX>>,
        old_value: Option<&PackingBatch<TX>>,
    ) {
        match (value, old_value) {
            (Some(v), _) => {
                self.insert(*key, v.first_gas_price());
            }
            (None, Some(_)) => {
                self.remove(key);
            }
            (None, None) => {}
        }
    }

    fn len(&self) -> usize { self.0.len() }

    #[inline]
    fn get_sort_key(&self, key: &TX::Sender) -> Option<U256> {
        self.get(key).cloned()
    }

    #[inline]
    fn make_sort_key(
        &self, _key: &TX::Sender, value: &PackingBatch<TX>,
    ) -> U256 {
        value.first_gas_price()
    }
}
