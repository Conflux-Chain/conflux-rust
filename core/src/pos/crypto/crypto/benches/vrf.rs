#[macro_use]
extern crate criterion;
use criterion::{BatchSize, Criterion};
use diem_crypto::{
    ec_vrf::EcVrfPrivateKey, traits::Uniform, vrf_number_with_nonce, HashValue,
    VRFPrivateKey, VRFProof,
};
use rand::{random, rngs::ThreadRng, thread_rng};

fn compute(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let priv_key = EcVrfPrivateKey::generate(&mut csprng);

    c.bench_function("vrf proof generation", |b| {
        b.iter_batched(
            || random::<u64>(),
            |nonce| priv_key.compute(&nonce.to_be_bytes()),
            BatchSize::SmallInput,
        )
    });
}

fn hash_vrf_number(c: &mut Criterion) {
    let vrf_output = HashValue::random();

    c.bench_function("hash of empty message", |b| {
        b.iter(|| HashValue::sha3_256_of(&[]))
    });

    c.bench_function("hash of hash", |b| {
        b.iter(|| HashValue::sha3_256_of(vrf_output.as_ref()))
    });

    c.bench_function("vrf number hash", |b| {
        b.iter(|| vrf_number_with_nonce(&vrf_output, 0))
    });

    let mut csprng: ThreadRng = thread_rng();
    let priv_key = EcVrfPrivateKey::generate(&mut csprng);
    let proof = priv_key.compute(&[]).unwrap();

    c.bench_function("vrf proof to hash", |b| {
        b.iter(|| proof.to_hash().unwrap())
    });

    c.bench_function("hash comparison", |b| {
        b.iter_batched(
            || (HashValue::random(), HashValue::random()),
            |(h1, h2)| h1 <= h2,
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(vrf_benches, compute, hash_vrf_number);
criterion_main!(vrf_benches);
