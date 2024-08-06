use std::collections::HashMap;

use crate::state::{global_stat::GlobalStat, overlay_account::AccountEntry};
use cfx_types::AddressWithSpace;
use parking_lot::RwLock;

use super::State;

pub struct SavedState {
    cache: HashMap<AddressWithSpace, AccountEntry>,
    global_stat: GlobalStat,
}

impl State {
    pub fn save(&self) -> SavedState {
        assert!(self.no_checkpoint());
        let cache = self
            .cache
            .read()
            .iter()
            .map(|(k, v)| (*k, v.clone_account()))
            .collect();
        SavedState {
            cache,
            global_stat: self.global_stat.clone(),
        }
    }

    pub fn restore(&mut self, saved: SavedState) {
        assert!(self.no_checkpoint());
        self.cache = RwLock::new(saved.cache);
        self.global_stat = saved.global_stat;
    }
}
