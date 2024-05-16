use cfx_types::U512;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::hint::black_box;
use treap_map::{
    ConsoliableWeight, SearchDirection, SharedKeyTreapMapConfig, TreapMap,
};

pub struct SmallWeight;
impl SharedKeyTreapMapConfig for SmallWeight {
    type Key = usize;
    type Value = usize;
    type Weight = u64;
}

pub struct LargeWeight;
impl SharedKeyTreapMapConfig for LargeWeight {
    type Key = usize;
    type Value = usize;
    type Weight = U512;
}

pub struct NoWeight;
impl SharedKeyTreapMapConfig for NoWeight {
    type Key = usize;
    type Value = usize;
    type Weight = treap_map::NoWeight;
}

const SIZE: usize = 1 << 12 - 1;

fn make_small_weight_map(mut rng: impl Rng) -> TreapMap<SmallWeight> {
    let mut treap_map = TreapMap::<SmallWeight>::new();
    for _ in 0..SIZE {
        let key = rng.gen::<usize>() % (SIZE * 2);
        treap_map.insert(key, key, rng.gen::<u64>() >> 14);
    }
    treap_map
}

fn make_large_weight_map(mut rng: impl Rng) -> TreapMap<LargeWeight> {
    let mut treap_map = TreapMap::<LargeWeight>::new();
    for _ in 0..SIZE {
        let key = rng.gen::<usize>() % (SIZE * 2);
        treap_map.insert(key, key, U512(rng.gen::<[u64; 8]>()) >> 14);
    }
    treap_map
}

fn make_no_weight_map(mut rng: impl Rng) -> TreapMap<NoWeight> {
    let mut treap_map = TreapMap::<NoWeight>::new();
    for _ in 0..SIZE {
        let key = rng.gen::<usize>() % (SIZE * 2);
        treap_map.insert(key, key, treap_map::NoWeight);
    }
    treap_map
}

fn bench_small_weight_search(c: &mut Criterion) {
    c.bench_function(
        "Search with u64 Weight (Actual Compute Weight)",
        move |b| {
            let treap_map = make_small_weight_map(StdRng::from_seed([123; 32]));
            let mut rand = XorShiftRng::from_entropy();
            b.iter(|| {
                black_box({
                    let key = rand.next_u64() as usize % (SIZE * 2);
                    black_box(treap_map.search(|left_weight, node| {
                        if node.value <= key {
                            SearchDirection::Right(u64::consolidate(
                                left_weight,
                                &node.weight,
                            ))
                        } else {
                            SearchDirection::LeftOrStop
                        }
                    }));
                })
            });
        },
    );
}

fn bench_large_weight_search(c: &mut Criterion) {
    c.bench_function(
        "Search with U512 Weight (Actual Compute Weight)",
        move |b| {
            let treap_map = make_large_weight_map(StdRng::from_seed([123; 32]));
            let mut rand = XorShiftRng::from_entropy();
            b.iter(|| {
                black_box({
                    let key = rand.next_u64() as usize % (SIZE * 2);
                    black_box(treap_map.search(|left_weight, node| {
                        if node.value <= key {
                            SearchDirection::Right(U512::consolidate(
                                left_weight,
                                &node.weight,
                            ))
                        } else {
                            SearchDirection::LeftOrStop
                        }
                    }));
                })
            });
        },
    );

    c.bench_function("`search_no_weight` function", move |b| {
        let mut rand = XorShiftRng::from_entropy();
        let treap_map = make_large_weight_map(StdRng::from_seed([123; 32]));

        b.iter(|| {
            black_box({
                let key = rand.next_u64() as usize % (SIZE * 2);
                black_box(treap_map.search_no_weight(|node| {
                    if node.value <= key {
                        SearchDirection::Right(())
                    } else {
                        SearchDirection::LeftOrStop
                    }
                }));
            })
        });
    });
}

fn bench_no_weight_search(c: &mut Criterion) {
    c.bench_function("Search treap-map without weight", move |b| {
        let treap_map = make_no_weight_map(StdRng::from_seed([123; 32]));
        let mut rand = XorShiftRng::from_entropy();
        b.iter(|| {
            black_box({
                let key = rand.next_u64() as usize % (SIZE * 2);
                black_box(treap_map.search(|_, node| {
                    if node.value <= key {
                        SearchDirection::Right(treap_map::NoWeight)
                    } else {
                        SearchDirection::LeftOrStop
                    }
                }));
            })
        });
    });
}

criterion_group!(
    benches,
    bench_small_weight_search,
    bench_large_weight_search,
    bench_no_weight_search
);
criterion_main!(benches);
