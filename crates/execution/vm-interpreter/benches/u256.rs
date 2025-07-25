use cfx_types::U256;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

const ONE: U256 = U256([1, 0, 0, 0]);
const TWO: U256 = U256([2, 0, 0, 0]);
const TWO_POW_5: U256 = U256([0x20, 0, 0, 0]);
const TWO_POW_8: U256 = U256([0x100, 0, 0, 0]);
const TWO_POW_16: U256 = U256([0x10000, 0, 0, 0]);
const TWO_POW_24: U256 = U256([0x1000000, 0, 0, 0]);
const TWO_POW_64: U256 = U256([0, 0x1, 0, 0]); // 0x1 00000000 00000000
const TWO_POW_96: U256 = U256([0, 0x100000000, 0, 0]); //0x1 00000000 00000000 00000000
const TWO_POW_224: U256 = U256([0, 0, 0, 0x100000000]); //0x1 00000000 00000000 00000000 00000000 00000000 00000000 00000000
const TWO_POW_248: U256 = U256([0, 0, 0, 0x100000000000000]); //0x1 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000

fn optimized_div(a: U256, b: U256) -> U256 {
    if !b.is_zero() {
        // match b {
        //     ONE => a,
        //     TWO => a >> 1,
        //     TWO_POW_5 => a >> 5,
        //     TWO_POW_8 => a >> 8,
        //     TWO_POW_16 => a >> 16,
        //     TWO_POW_24 => a >> 24,
        //     TWO_POW_64 => a >> 64,
        //     TWO_POW_96 => a >> 96,
        //     TWO_POW_224 => a >> 224,
        //     TWO_POW_248 => a >> 248,
        //     _ => a / b,
        // }
        if b == ONE {
            a
        } else if b == TWO {
            a >> 1
        } else if b == TWO_POW_5 {
            a >> 5
        } else if b == TWO_POW_8 {
            a >> 8
        } else if b == TWO_POW_16 {
            a >> 16
        } else if b == TWO_POW_24 {
            a >> 24
        } else if b == TWO_POW_64 {
            a >> 64
        } else if b == TWO_POW_96 {
            a >> 96
        } else if b == TWO_POW_224 {
            a >> 224
        } else if b == TWO_POW_248 {
            a >> 248
        } else {
            a / b
        }
    } else {
        U256::zero()
    }
}

fn normal_div(a: U256, b: U256) -> U256 {
    if !b.is_zero() {
        a / b
    } else {
        U256::zero()
    }
}

fn bench_u256_div(c: &mut Criterion) {
    let mut group = c.benchmark_group("U256 Division Special Cases");
    for i in [2u64, 256u64, 0x100000000000000u64].iter() {
        group.bench_with_input(BenchmarkId::new("Common", i), i, |b, i| {
            b.iter(|| normal_div(U256::from(10000), U256::from(*i)))
        });
        group.bench_with_input(BenchmarkId::new("Optimized", i), i, |b, i| {
            b.iter(|| optimized_div(U256::from(10000), U256::from(*i)))
        });
    }
    group.finish();

    let mut group = c.benchmark_group("U256 Division Normal Cases");
    for i in [3u64, 6u64].iter() {
        group.bench_with_input(BenchmarkId::new("Common", i), i, |b, i| {
            b.iter(|| normal_div(U256::from(10000), U256::from(*i)))
        });
        group.bench_with_input(BenchmarkId::new("Optimized", i), i, |b, i| {
            b.iter(|| optimized_div(U256::from(10000), U256::from(*i)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_u256_div);
criterion_main!(benches);
