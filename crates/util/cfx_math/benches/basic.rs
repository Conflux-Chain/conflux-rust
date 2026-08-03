use cfx_types::U256;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

fn bench_random_input(c: &mut Criterion) {
    c.bench_function("u64 input gen", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| rng.random::<u64>());
    });

    c.bench_function("u128 input gen", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| rng.random::<u128>());
    });

    c.bench_function("u256 input gen", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| U256(rng.random()));
    });
}

fn bench_u256_basic_op(c: &mut Criterion) {
    c.bench_function("u256 / u256", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| U256(rng.random()) / (U256(rng.random()) >> 64));
    });

    c.bench_function("u256 / u64", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| U256(rng.random()) / rng.random::<u64>());
    });

    c.bench_function("u256 small quo (4 bit)", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| U256(rng.random()) / (U256(rng.random()) >> 4));
    });

    c.bench_function("u256 small quo (2 bit)", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| U256(rng.random()) / (U256(rng.random()) >> 2));
    });

    c.bench_function("u256 small quo (0 bit)", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| {
            let a = U256(rng.random());
            (a >> 1) / a
        })
    });
}

fn bench_u128_basic_op(c: &mut Criterion) {
    c.bench_function("u128 / u128", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| rng.random::<u128>() / (rng.random::<u128>() >> 32));
    });

    c.bench_function("u128 / u64", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| rng.random::<u128>() / rng.random::<u64>() as u128);
    });

    c.bench_function("u128 small quo (4 bit)", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| rng.random::<u128>() / (rng.random::<u128>() >> 4));
    });

    c.bench_function("u128 small quo (2 bit)", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| rng.random::<u128>() / (rng.random::<u128>() >> 2));
    });

    c.bench_function("u128 small quo (0 bit)", move |b| {
        let mut rng = XorShiftRng::from_os_rng();
        b.iter(|| {
            let a = rng.random::<u128>();
            (a >> 1) / a
        })
    });
}

criterion_group!(
    benches,
    bench_random_input,
    bench_u128_basic_op,
    bench_u256_basic_op
);
criterion_main!(benches);
