// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use treap_map::{SharedKeyTreapMapConfig, TreapMap};

pub struct CombinedMap;
impl SharedKeyTreapMapConfig for CombinedMap {
    type Key = usize;
    type Value = usize;
    type Weight = u64;
}

const SIZE: usize = 1 << 20 - 1;

fn make_combined_map(mut rng: impl Rng) -> TreapMap<CombinedMap> {
    let mut treap_map = TreapMap::<CombinedMap>::new();
    for _ in 0..SIZE {
        let key = rng.gen::<usize>() % (SIZE * 2);
        treap_map.insert(key, key, rng.gen::<u64>() % u32::MAX as u64);
    }
    treap_map
}

pub struct SepreateMap;
impl SharedKeyTreapMapConfig for SepreateMap {
    type Key = usize;
    type Value = ();
    type Weight = u64;
}

fn make_seperate_map(
    mut rng: impl Rng,
) -> (TreapMap<SepreateMap>, BTreeMap<usize, usize>) {
    let mut treap_map = TreapMap::<SepreateMap>::new();
    let mut btree_map: BTreeMap<usize, usize> = BTreeMap::new();
    for _ in 0..SIZE {
        let key = rng.gen::<usize>() % (SIZE * 2);
        btree_map.insert(key, key);
        treap_map.insert(key, (), rng.gen::<u64>() % u32::MAX as u64);
    }
    (treap_map, btree_map)
}

fn bench_combined_treap_map_query(c: &mut Criterion) {
    let treap_map = make_combined_map(StdRng::from_seed([123; 32]));
    c.bench_function("Combined Treapmap get", move |b| {
        let mut key = 0usize;
        b.iter(|| {
            black_box({
                key = rand::random::<usize>() % (SIZE * 2);
                black_box(treap_map.get(&key).unwrap_or(&key));
            })
        });
    });
}

fn bench_combined_treap_map_update(c: &mut Criterion) {
    let mut treap_map = make_combined_map(StdRng::from_seed([123; 32]));
    c.bench_function("Combined Treapmap update", move |b| {
        b.iter(|| {
            let key = rand::random::<usize>() % (SIZE * 2);
            if treap_map.len() > SIZE {
                treap_map.remove(&key);
            } else {
                treap_map.insert(
                    key,
                    rand::random(),
                    rand::random::<u64>() % u32::MAX as u64,
                );
            }
        });
    });
}

fn bench_sepreate_treap_map_query(c: &mut Criterion) {
    let (treap_map, btree_map) =
        make_seperate_map(StdRng::from_seed([123; 32]));
    c.bench_function("Seperate Treapmap get", move |b| {
        b.iter(|| {
            let key = rand::random::<usize>() % (SIZE * 2);
            black_box(btree_map.get(&key));
        })
    });
    black_box(treap_map);
}

fn bench_sepreate_treap_map_update(c: &mut Criterion) {
    let (mut treap_map, mut btree_map) =
        make_seperate_map(StdRng::from_seed([123; 32]));
    c.bench_function("Seperate Treapmap update", move |b| {
        b.iter(|| {
            let key = rand::random::<usize>() % (SIZE * 2);
            if treap_map.len() > SIZE {
                treap_map.remove(&key);
                btree_map.remove(&key);
            } else {
                btree_map.insert(key, rand::random());
                treap_map.insert(
                    key,
                    (),
                    rand::random::<u64>() % u32::MAX as u64,
                );
            }
        });
    });
}

criterion_group!(
    benches,
    bench_combined_treap_map_query,
    bench_combined_treap_map_update,
    bench_sepreate_treap_map_query,
    bench_sepreate_treap_map_update
);
criterion_main!(benches);
