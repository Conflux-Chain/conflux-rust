#[macro_use]
extern crate criterion;
use criterion::{BatchSize, Criterion};
use diem_crypto::{ec_vrf::EcVrfPrivateKey, traits::Uniform, VRFPrivateKey};
use rand::{random, rngs::ThreadRng, thread_rng};

fn compute(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let priv_key = EcVrfPrivateKey::generate(&mut csprng);

    c.bench_function("vrf proof generation with same seed", |b| {
        b.iter(|| priv_key.compute(&[]))
    });

    c.bench_function("vrf proof generation", |b| {
        b.iter_batched(
            || random::<u64>(),
            |nonce| priv_key.compute(&nonce.to_be_bytes()),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(vrf_benches, compute);
criterion_main!(vrf_benches);
