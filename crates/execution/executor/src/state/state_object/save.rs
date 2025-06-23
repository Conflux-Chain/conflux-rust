use std::collections::HashMap;

use crate::state::{global_stat::GlobalStat, overlay_account::AccountEntry};
use cfx_types::AddressWithSpace;

use super::State;

pub struct SavedState {
    committed_cache: HashMap<AddressWithSpace, AccountEntry>,
    global_stat: GlobalStat,
}

impl State {
    pub fn save(&mut self) -> SavedState {
        self.commit_cache(false);
        let committed_cache = self
            .committed_cache
            .iter()
            .map(|(k, v)| (*k, v.clone_account()))
            .collect();
        SavedState {
            committed_cache,
            global_stat: self.global_stat.clone(),
        }
    }

    pub fn restore(&mut self, saved: SavedState) {
        assert!(self.no_checkpoint());
        self.cache = Default::default();
        self.committed_cache = saved.committed_cache;
        self.global_stat = saved.global_stat;
    }
}
