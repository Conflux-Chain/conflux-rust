#[macro_use]
extern crate criterion;
use criterion::Criterion;
use diem_crypto::{
    bls::*,
    traits::{SigningKey, Uniform},
    ValidCryptoMaterial,
};
use diem_crypto_derive::{BCSCryptoHash, CryptoHasher};
use rand::{rngs::ThreadRng, thread_rng};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Debug, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct TestDiemCrypto(pub String);

fn decode(c: &mut Criterion) {
    let mut csprng: ThreadRng = thread_rng();
    let priv_key = BLSPrivateKey::generate(&mut csprng);
    let msg = TestDiemCrypto("".to_string());
    let sig: BLSSignature = priv_key.sign(&msg);
    let sig_bytes = sig.to_bytes();

    c.bench_function("bls signature decoding", move |b| {
        b.iter(|| BLSSignature::try_from(sig_bytes.as_slice()).unwrap())
    });
}

criterion_group!(bls_benches, decode);
criterion_main!(bls_benches);
