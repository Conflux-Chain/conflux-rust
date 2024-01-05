// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use heap_map::HeapMap;

fn bench_heapmap_insert(c: &mut Criterion) {
    let mut heapmap = HeapMap::<usize, u64>::new();
    const SIZE: usize = 1000000usize;
    let key = || rand::random::<usize>() % (SIZE * 2);
    for _ in 0..SIZE {
        heapmap.insert(&key(), rand::random());
    }
    c.bench_function("Heapmap insert/remove", move |b| {
        b.iter(|| {
            let value = if heapmap.len() > SIZE {
                black_box(rand::random::<u64>());
                heapmap.remove(&key())
            } else {
                heapmap.insert(&key(), rand::random())
            };
            black_box(value)
        });
    });
}

fn bench_overhead(c: &mut Criterion) {
    const SIZE: usize = 1000000usize;
    let key = || rand::random::<usize>() % (SIZE * 2);
    c.bench_function("Pick random input cost", move |b| {
        b.iter(|| black_box((key(), rand::random::<u64>())))
    });
}

criterion_group!(benches, bench_heapmap_insert, bench_overhead);
criterion_main!(benches);
