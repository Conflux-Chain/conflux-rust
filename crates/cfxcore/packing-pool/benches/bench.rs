// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::atomic::AtomicUsize;

use cfx_packing_pool::{MockTransaction, PackingPool, PackingPoolConfig};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{distributions::Uniform, Rng, RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

fn default_tx(sender: u64, gas_limit: u64, gas_price: u64) -> MockTransaction {
    static ID: AtomicUsize = AtomicUsize::new(0);
    MockTransaction {
        sender,
        nonce: 0,
        gas_price,
        gas_limit,
        id: ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
    }
}

fn random_tx<R: SeedableRng + RngCore>(rng: &mut R) -> MockTransaction {
    let i = rng.next_u64() % 1000;
    let mut gas_limit = 1.01f64.powf(2000.0 + i as f64) as u64;
    gas_limit -= gas_limit / rng.sample(Uniform::new(200, 2000));
    let mut gas_price = 1.01f64.powf(3000.0 - i as f64) as u64;
    gas_price -= gas_price / rng.sample(Uniform::new(200, 2000));
    default_tx(i, gas_price, gas_limit)
}

fn bench_pool() -> PackingPool<MockTransaction> {
    let mut rand = XorShiftRng::from_entropy();
    let mut pool =
        PackingPool::new(PackingPoolConfig::new(3_000_000.into(), 20, 4));
    for i in 0..10000 {
        let mut gas_limit = 1.001f64.powf(20000.0 + i as f64) as u64;
        gas_limit -= gas_limit / rand.sample(Uniform::new(500, 2000));
        let mut gas_price = 1.001f64.powf(30000.0 - i as f64) as u64;
        gas_price -= gas_price / rand.sample(Uniform::new(500, 2000));

        let tx = default_tx(i, gas_limit, gas_price);

        let _ = pool.insert(tx);
    }
    return pool;
}

fn bench_insert(c: &mut Criterion) {
    c.bench_function("Make random TX", move |b| {
        let mut rng = XorShiftRng::from_entropy();
        b.iter(|| {
            std::hint::black_box(random_tx(&mut rng));
        });
    });
    c.bench_function("Random pool insert", move |b| {
        let mut pool = bench_pool();
        let mut rng = XorShiftRng::from_entropy();
        b.iter(|| {
            let _ = pool.insert(random_tx(&mut rng));
        });
    });
}

fn bench_sample(c: &mut Criterion) {
    c.bench_function("Make sampler", move |b| {
        let pool = bench_pool();
        let mut rng = XorShiftRng::from_entropy();
        b.iter(|| {
            let block_gas_limit = 1.001f64
                .powf(rng.sample(Uniform::new(19000, 33000)) as f64)
                as u64;
            let _ = std::hint::black_box(
                pool.tx_sampler(&mut rng, block_gas_limit.into()),
            );
        });
    });

    c.bench_function("Random pool sample (all random pick) (100x)", move |b| {
        let pool = bench_pool();
        let mut rng = XorShiftRng::from_entropy();
        let block_gas_limit = 1.001f64.powf(27000.0) as u64;
        b.iter(|| {
            let mut sampler = pool.tx_sampler(&mut rng, block_gas_limit.into());
            for _ in 0..100 {
                std::hint::black_box(sampler.next());
            }
        });
    });

    c.bench_function(
        "Random pool sample (2/3 random pick + 1/3 candidate) (10000x)",
        move |b| {
            let pool = bench_pool();
            let mut rng = XorShiftRng::from_entropy();
            let block_gas_limit = 1.001f64.powf(35299.0) as u64;
            b.iter(|| {
                let mut sampler =
                    pool.tx_sampler(&mut rng, block_gas_limit.into());
                for _ in 0..10000 {
                    std::hint::black_box(sampler.next());
                }
            });
        },
    );
}

criterion_group!(benches, bench_insert, bench_sample);
criterion_main!(benches);
