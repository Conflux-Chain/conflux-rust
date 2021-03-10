// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::{recent_lfu::*, *},
    *,
};
use rand::distributions::{uniform::*, *};

struct CacheUtil<'a> {
    cache_algo_data: &'a mut [RecentLFUHandle<u32>],
    most_recent_key: Option<i32>,
}

impl<'a> CacheStoreUtil for CacheUtil<'a> {
    type CacheAlgoData = RecentLFUHandle<u32>;
    type ElementIndex = i32;

    fn get(&self, element_index: i32) -> RecentLFUHandle<u32> {
        match self.most_recent_key {
            None => {}
            Some(key) => {
                assert_ne!(key, element_index);
            }
        }

        let ret = self.cache_algo_data[element_index as usize];
        assert_eq!(true, ret.is_lru_hit());
        ret
    }

    fn get_most_recently_accessed(
        &self, element_index: i32,
    ) -> RecentLFUHandle<u32> {
        assert_eq!(Some(element_index), self.most_recent_key);
        self.cache_algo_data[element_index as usize]
    }

    fn set(&mut self, element_index: i32, algo_data: &RecentLFUHandle<u32>) {
        match self.most_recent_key {
            None => {}
            Some(key) => {
                assert_ne!(key, element_index);
            }
        }

        let old = self.cache_algo_data[element_index as usize];
        assert_eq!(true, old.is_lru_hit());

        self.cache_algo_data[element_index as usize] = *algo_data;
    }

    fn set_most_recently_accessed(
        &mut self, element_index: i32, algo_data: &RecentLFUHandle<u32>,
    ) {
        // If access then check the most recently accessed key.
        // If delete the most_recent_key is none and there is nothing to check.
        if self.most_recent_key.is_some() {
            assert_eq!(self.most_recent_key, Some(element_index));
        }
        self.cache_algo_data[element_index as usize] = *algo_data;
    }
}

impl<'a> CacheUtil<'a> {
    fn prepare(&mut self, key: i32) {
        self.most_recent_key = Some(key);
    }

    fn done(&mut self, _key: i32) {
        self.most_recent_key.take();
    }
}

#[derive(Debug)]
enum KeyActions {
    Access(i32),
    Delete(i32),
}

#[test]
fn r_lfu_algorithm_smoke_test() {
    let key_range = 10;

    let mut cache_algo_data =
        vec![RecentLFUHandle::<u32>::default(); key_range as usize];

    let mut cache_util = CacheUtil {
        cache_algo_data: &mut cache_algo_data,
        most_recent_key: None,
    };

    let mut lfru = RecentLFU::<u32, i32>::new(3, 6);

    let mut cache_actions = vec![
        KeyActions::Access(0),
        KeyActions::Access(1),
        KeyActions::Access(1),
        KeyActions::Access(2),
        KeyActions::Access(2),
        KeyActions::Access(2),
        KeyActions::Access(3),
        KeyActions::Access(4),
        KeyActions::Access(5),
        // Test deletion of non LFU item.
        KeyActions::Delete(0),
        KeyActions::Access(5),
        KeyActions::Access(1),
        KeyActions::Access(6),
        KeyActions::Access(7),
        KeyActions::Access(8),
        KeyActions::Access(9),
        // Test frequency counter of ghost item.
        KeyActions::Access(5),
        KeyActions::Access(1),
        KeyActions::Access(9),
        KeyActions::Delete(1),
        KeyActions::Access(7),
        KeyActions::Access(8),
        KeyActions::Access(9),
        KeyActions::Access(5),
        KeyActions::Access(1),
        // Test frequency counter of final state.
    ];

    let state_check_pos = cache_actions.len();

    let mut rng = get_rng_for_test();

    let candidate_sampler = Uniform::new(0, key_range);
    let probability_sampler = Uniform::new(0.0, 1.0);
    let delete_probability = 0.1;
    for _actions in 1..10000 {
        let key = candidate_sampler.sample(&mut rng);

        if probability_sampler.sample(&mut rng) >= delete_probability {
            cache_actions.push(KeyActions::Access(key));
        } else {
            cache_actions.push(KeyActions::Delete(key));
        }
    }

    let mut pos = 0;
    for action in cache_actions.iter() {
        if pos == state_check_pos {
            // TODO(yz): check final state after hard coded sequence.
        }
        pos += 1;
        match *action {
            KeyActions::Delete(key) => {
                cache_util.done(key);
                if cache_util.cache_algo_data[key as usize].is_lru_hit() {
                    lfru.delete(key, &mut cache_util);
                    assert_eq!(
                        false,
                        cache_util.cache_algo_data[key as usize].is_lru_hit()
                    );
                }
            }
            KeyActions::Access(key) => {
                cache_util.prepare(key);
                match lfru.access(key, &mut cache_util) {
                    CacheAccessResult::MissReplaced {
                        evicted: evicted_keys,
                        evicted_keep_cache_algo_data: _,
                    } => {
                        for evicted in evicted_keys {
                            cache_util.cache_algo_data[evicted as usize]
                                .set_evicted();
                        }
                    }
                    _ => {}
                }
                cache_util.done(key);
            }
        }
    }
}
