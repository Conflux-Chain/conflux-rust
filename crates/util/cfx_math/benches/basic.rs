use cfx_types::U256;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

fn bench_random_input(c: &mut Criterion) {
    c.bench_function("u64 input gen", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| rng.gen::<u64>());
    });

    c.bench_function("u128 input gen", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| rng.gen::<u128>());
    });

    c.bench_function("u256 input gen", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| U256(rng.gen()));
    });
}

fn bench_u256_basic_op(c: &mut Criterion) {
    c.bench_function("u256 / u256", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| U256(rng.gen()) / (U256(rng.gen()) >> 64));
    });

    c.bench_function("u256 / u64", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| U256(rng.gen()) / rng.gen::<u64>());
    });

    c.bench_function("u256 small quo (4 bit)", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| U256(rng.gen()) / (U256(rng.gen()) >> 4));
    });

    c.bench_function("u256 small quo (2 bit)", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| U256(rng.gen()) / (U256(rng.gen()) >> 2));
    });

    c.bench_function("u256 small quo (0 bit)", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| {
            let a = U256(rng.gen());
            (a >> 1) / a
        })
    });
}

fn bench_u128_basic_op(c: &mut Criterion) {
    c.bench_function("u128 / u128", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| rng.gen::<u128>() / (rng.gen::<u128>() >> 32));
    });

    c.bench_function("u128 / u64", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| rng.gen::<u128>() / rng.gen::<u64>() as u128);
    });

    c.bench_function("u128 small quo (4 bit)", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| rng.gen::<u128>() / (rng.gen::<u128>() >> 4));
    });

    c.bench_function("u128 small quo (2 bit)", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| rng.gen::<u128>() / (rng.gen::<u128>() >> 2));
    });

    c.bench_function("u128 small quo (0 bit)", move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| {
            let a = rng.gen::<u128>();
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
