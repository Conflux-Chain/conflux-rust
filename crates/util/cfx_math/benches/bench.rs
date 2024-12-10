use cfx_math::{
    nth_inv_root,
    nth_root::{nth_root, RootDegree, RootInvParams},
};
use cfx_types::U256;
use criterion::{criterion_group, criterion_main, Criterion};
use num::integer::Roots;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

fn bench_nth_root<N: RootDegree>(c: &mut Criterion) {
    c.bench_function(&format!("u64 {}-th root", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| nth_root::<N, u64>(rng.gen()));
    });

    c.bench_function(&format!("u64 {}-th baseline", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| rng.gen::<u64>().nth_root(N::U32));
    });

    c.bench_function(&format!("u128 {}-th root", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| nth_root::<N, u128>(rng.gen()));
    });
    c.bench_function(&format!("u128 {}-th baseline", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| rng.gen::<u128>().nth_root(N::U32));
    });

    c.bench_function(&format!("u192 {}-th root", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| nth_root::<N, U256>(U256(rng.gen()) >> 64));
    });

    c.bench_function(&format!("u256 {}-th root", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| nth_root::<N, U256>(U256(rng.gen())));
    });
}

fn bench_nth_inv_root<N: RootDegree>(c: &mut Criterion)
where
    (N, typenum::U10): RootInvParams,
    (N, typenum::U15): RootInvParams,
    (N, typenum::U20): RootInvParams,
{
    c.bench_function(&format!("{}-th inv root (10 bit)", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| {
            nth_inv_root::<N, typenum::U10>(U256::from(rng.gen::<u64>()))
        });
    });

    c.bench_function(&format!("{}-th inv root (15 bit)", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| {
            nth_inv_root::<N, typenum::U15>(U256::from(rng.gen::<u64>()))
        });
    });

    c.bench_function(&format!("{}-th inv root (20 bit)", N::USIZE), move |b| {
        let mut rng = XorShiftRng::from_seed([0u8; 16]);
        b.iter(|| {
            nth_inv_root::<N, typenum::U20>(U256::from(rng.gen::<u64>()))
        });
    });
}

fn bench_multiple_nth_root(c: &mut Criterion) {
    bench_nth_root::<typenum::U2>(c);
    bench_nth_root::<typenum::U3>(c);
    bench_nth_root::<typenum::U4>(c);
    bench_nth_root::<typenum::U5>(c);
    bench_nth_root::<typenum::U8>(c);
    bench_nth_root::<typenum::U10>(c);
    bench_nth_root::<typenum::U12>(c);

    // c.bench_function(&format!("u256 another sqrt"), move |b| {
    //     b.iter(|| cfx_math::sqrt_u256(U256(rand::random::<[u64; 4]>())));
    // });
}

fn bench_multiple_nth_inv_root(c: &mut Criterion) {
    bench_nth_inv_root::<typenum::U2>(c);
    bench_nth_inv_root::<typenum::U3>(c);
    bench_nth_inv_root::<typenum::U4>(c);
    bench_nth_inv_root::<typenum::U5>(c);
    bench_nth_inv_root::<typenum::U8>(c);
    bench_nth_inv_root::<typenum::U10>(c);
    bench_nth_inv_root::<typenum::U12>(c);
}

criterion_group!(
    benches,
    bench_multiple_nth_inv_root,
    bench_multiple_nth_root
);
criterion_main!(benches);
