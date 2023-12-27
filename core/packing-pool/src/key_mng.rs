use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use cfx_types::U256;
use treap_map::KeyMngTrait;

use super::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
};

#[derive(Default, Clone)]
pub(crate) struct PackingPoolExtMap<K>(BTreeMap<K, U256>);

impl<K> Deref for PackingPoolExtMap<K> {
    type Target = BTreeMap<K, U256>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<K> DerefMut for PackingPoolExtMap<K> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl<TX: PackingPoolTransaction> KeyMngTrait<PackingPoolMap<TX>>
    for PackingPoolExtMap<TX::Sender>
{
    #[inline]
    fn view_update(
        &mut self, key: &TX::Sender, value: Option<&Vec<TX>>,
        old_value: Option<&Vec<TX>>,
    )
    {
        match (value, old_value) {
            (Some(v), _) => {
                self.insert(*key, v.first().unwrap().gas_price());
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
    fn make_sort_key(&self, _key: &TX::Sender, value: &Vec<TX>) -> U256 {
        value.first().unwrap().gas_price()
    }
}
