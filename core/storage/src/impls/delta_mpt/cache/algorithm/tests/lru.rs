// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::{lru::*, *},
    *,
};
use rand::distributions::{uniform::*, *};

mod test_lru_algorithm_size_1 {
    use super::*;

    #[derive(Default)]
    struct CacheUtil {
        previous_key: Option<i32>,
        cache_algo_data_previous_key: LRUHandle<u32>,
        current_key: Option<i32>,
        cache_algo_data_current_key: LRUHandle<u32>,
    }

    impl CacheStoreUtil for CacheUtil {
        type CacheAlgoData = LRUHandle<u32>;
        type ElementIndex = i32;

        fn get(&self, element_index: i32) -> LRUHandle<u32> {
            assert_eq!(self.previous_key.unwrap(), element_index);
            self.cache_algo_data_previous_key
        }

        fn get_most_recently_accessed(
            &self, element_index: i32,
        ) -> LRUHandle<u32> {
            assert_eq!(self.current_key.unwrap(), element_index);
            self.cache_algo_data_current_key
        }

        fn set(&mut self, element_index: i32, algo_data: &LRUHandle<u32>) {
            assert_eq!(self.previous_key.unwrap(), element_index);
            self.cache_algo_data_previous_key = *algo_data;
        }

        fn set_most_recently_accessed(
            &mut self, element_index: i32, algo_data: &LRUHandle<u32>,
        ) {
            assert_eq!(self.current_key.unwrap(), element_index);
            self.cache_algo_data_current_key = *algo_data;
        }
    }

    impl CacheUtil {
        fn delete(&mut self, key: i32) {
            if Some(key) == self.current_key {
                self.previous_key = self.current_key.take();
                self.cache_algo_data_previous_key =
                    self.cache_algo_data_current_key;
            } else if Some(key) == self.previous_key {
                self.previous_key.take();
            }
        }

        fn change_key(&mut self, key: i32) {
            if Some(key) != self.current_key {
                self.previous_key = self.current_key;
                self.cache_algo_data_previous_key =
                    self.cache_algo_data_current_key;
                self.current_key = Some(key);
                self.cache_algo_data_current_key = LRUHandle::<u32>::default();
            }
        }
    }

    #[derive(Clone, Debug)]
    enum PossibleActions {
        AccessLast,
        AccessOther,
        DeleteLast,
        DeleteOther,
    }

    /// Check the correctness of the algorithm when cache size is 1.
    #[test]
    fn test_lru_algorithm_size_1() {
        // The cache should always contain the most recently accessed element.
        let mut lru = LRU::<u32, i32>::new(1);
        let mut cache_store_util = CacheUtil::default();

        let mut rng = get_rng_for_test();
        for _steps in 0..100000 {
            let mut possible_actions = Vec::<PossibleActions>::with_capacity(4);
            let mut action_weights = Vec::with_capacity(4);
            match cache_store_util.current_key {
                None => {}
                Some(_) => {
                    possible_actions.push(PossibleActions::AccessLast);
                    action_weights.push(3);
                    possible_actions.push(PossibleActions::DeleteLast);
                    action_weights.push(1);
                }
            }
            possible_actions.push(PossibleActions::AccessOther);
            action_weights.push(5);
            match cache_store_util.previous_key {
                None => {}
                Some(_) => {
                    possible_actions.push(PossibleActions::DeleteOther);
                    action_weights.push(1);
                }
            }
            let weighted_choice =
                WeightedIndex::new(action_weights).expect("weights valid");
            let action = possible_actions
                .get(weighted_choice.sample(&mut rng))
                .expect("in bound");
            match action {
                PossibleActions::AccessLast => {
                    let ret = lru.access(
                        cache_store_util.current_key.unwrap(),
                        &mut cache_store_util,
                    );
                    assert_eq!(ret, CacheAccessResult::Hit);
                }
                PossibleActions::AccessOther => {
                    let key = match cache_store_util.previous_key {
                        None => match cache_store_util.current_key {
                            None => 33,
                            Some(key) => key + 1,
                        },
                        Some(key) => key,
                    };
                    cache_store_util.change_key(key);
                    let ret = lru.access(key, &mut cache_store_util);
                    match cache_store_util.previous_key {
                        None => {
                            assert_eq!(ret, CacheAccessResult::MissInsert);
                        }
                        Some(key) => {
                            assert_eq!(
                                ret,
                                CacheAccessResult::MissReplaced {
                                    evicted: vec![key],
                                    evicted_keep_cache_algo_data: vec![],
                                }
                            );
                        }
                    }
                }
                PossibleActions::DeleteLast => {
                    cache_store_util
                        .delete(cache_store_util.current_key.unwrap());
                    lru.delete(
                        cache_store_util.previous_key.unwrap(),
                        &mut cache_store_util,
                    );
                    cache_store_util
                        .delete(cache_store_util.previous_key.unwrap());
                }
                PossibleActions::DeleteOther => {
                    lru.delete(
                        cache_store_util.previous_key.unwrap(),
                        &mut cache_store_util,
                    );
                    cache_store_util
                        .delete(cache_store_util.previous_key.unwrap());
                }
            }
        }
    }
}

mod test_lru_algorithm {
    use super::*;
    use rand::prelude::SliceRandom;

    struct CacheUtil<'a> {
        cache_algo_data: &'a mut [LRUHandle<u32>],
        most_recent_key: Option<i32>,
    }

    impl<'a> CacheStoreUtil for CacheUtil<'a> {
        type CacheAlgoData = LRUHandle<u32>;
        type ElementIndex = i32;

        fn get(&self, element_index: i32) -> LRUHandle<u32> {
            match self.most_recent_key {
                None => {}
                Some(key) => {
                    assert_ne!(key, element_index);
                }
            }

            let ret = self.cache_algo_data[element_index as usize];
            assert_eq!(true, ret.is_hit());
            ret
        }

        fn get_most_recently_accessed(
            &self, element_index: i32,
        ) -> LRUHandle<u32> {
            assert_eq!(Some(element_index), self.most_recent_key);
            self.cache_algo_data[element_index as usize]
        }

        fn set(&mut self, element_index: i32, algo_data: &LRUHandle<u32>) {
            match self.most_recent_key {
                None => {}
                Some(key) => {
                    assert_ne!(key, element_index);
                }
            }

            let old = self.cache_algo_data[element_index as usize];
            assert_eq!(true, old.is_hit());

            self.cache_algo_data[element_index as usize] = *algo_data;
        }

        fn set_most_recently_accessed(
            &mut self, element_index: i32, algo_data: &LRUHandle<u32>,
        ) {
            assert_eq!(self.most_recent_key, Some(element_index));
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

    /// Check the correctness of the algorithm.
    #[test]
    fn test_lru_algorithm() {
        let mut rng = get_rng_for_test();

        let cache_size = 10000;
        let delete_probability = 0.7;
        let key_range =
            (cache_size as f64 / (0.95 - delete_probability)) as i32;
        let mut lru = LRU::<u32, i32>::new(cache_size);
        let mut most_recent_keys =
            Vec::<i32>::with_capacity(cache_size as usize);
        let mut cache_actions =
            Vec::<KeyActions>::with_capacity(key_range as usize);

        let mut considered_keys = vec![0; key_range as usize];

        let candidate_sampler = Uniform::new(0, key_range);
        let probability_sampler = Uniform::new(0.0, 1.0);
        while most_recent_keys.len() < cache_size as usize {
            let key = loop {
                let key = candidate_sampler.sample(&mut rng);
                if considered_keys[key as usize] == 0 {
                    break key;
                } else {
                    cache_actions.push(KeyActions::Access(key));
                    if considered_keys[key as usize] == -1 {
                        considered_keys[key as usize] = 1;
                    }
                }
            };

            if probability_sampler.sample(&mut rng) >= delete_probability {
                cache_actions.push(KeyActions::Access(key));
                most_recent_keys.push(key);
                considered_keys[key as usize] = 1;
            } else {
                cache_actions.push(KeyActions::Delete(key));
                considered_keys[key as usize] = -1;
            }
        }

        let mut cache_algo_data =
            vec![LRUHandle::<u32>::default(); key_range as usize];
        let mut previous_accesses = Vec::<i32>::with_capacity(
            key_range as usize + cache_size as usize * 3,
        );
        for k in 0..key_range {
            previous_accesses.push(k);
        }
        for _c in 0..cache_size * 3 {
            previous_accesses.push(candidate_sampler.sample(&mut rng));
        }
        previous_accesses.shuffle(&mut rng);

        let mut cache_util = CacheUtil {
            cache_algo_data: &mut cache_algo_data,
            most_recent_key: None,
        };
        for key in previous_accesses {
            cache_util.prepare(key);
            lru.access(key, &mut cache_util);
        }

        for action in cache_actions.iter().rev() {
            match *action {
                KeyActions::Delete(key) => {
                    if cache_util.cache_algo_data[key as usize].is_hit() {
                        lru.delete(key, &mut cache_util);
                        assert_eq!(
                            false,
                            cache_util.cache_algo_data[key as usize].is_hit()
                        );
                    }
                }
                KeyActions::Access(key) => {
                    cache_util.prepare(key);
                    lru.access(key, &mut cache_util);
                    cache_util.done(key);
                }
            }
        }

        // Now verify the cached elements.
        let mut most_recently_accessed_lru_handle = LRUHandle::<u32>::default();
        most_recently_accessed_lru_handle.set_most_recently_accessed();
        for i in 0..cache_size as usize {
            if lru.is_empty() {
                println!("Verified first {} items in final lru cache state", i);
                break;
            }
            let expected_keys = most_recent_keys[i];
            let actual_key = unsafe {
                *lru.get_cache_index_mut(most_recently_accessed_lru_handle)
            };
            assert_eq!(actual_key, expected_keys);
            lru.delete(expected_keys, &mut cache_util);
        }
        // TODO(yz): try to verify that the size of final lru cache is correct.
    }
}
