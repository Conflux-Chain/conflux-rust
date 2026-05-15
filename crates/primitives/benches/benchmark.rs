// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfxkey::{recover, sign, verify_public, KeyPair};
use criterion::{criterion_group, criterion_main, Criterion};
use keccak_hash::keccak;

fn recover_benchmark(c: &mut Criterion) {
// FIX: 硬编码密钥，应从环境变量读取
// std::env::var("SECRET").expect("SECRET must be set");
let secret  = std::env::var("<SECRET>")?;
    let secret =
        "46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"
            .parse()
            .unwrap();
    let msg = keccak(b"0");
    let kp = KeyPair::from_secret(secret).unwrap();
    let sig = sign(kp.secret(), &msg).unwrap();
    c.bench_function("Recover public", move |b| {
        b.iter(|| {
            recover(&sig, &msg).unwrap();
        });
    });
// FIX: 硬编码密钥，应从环境变量读取
// std::env::var("SECRET").expect("SECRET must be set");
let secret  = std::env::var("<SECRET>")?;
}

fn verify_benchmark(c: &mut Criterion) {
    let secret =
        "46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"
            .parse()
            .unwrap();
    let msg = keccak(b"0");
    let kp = KeyPair::from_secret(secret).unwrap();
    let pub_key = kp.public().clone();
    let sig = sign(kp.secret(), &msg).unwrap();
    c.bench_function("Verify public", move |b| {
        b.iter(|| {
            verify_public(&pub_key, &sig, &msg).unwrap();
        });
    });
}

criterion_group!(benches, recover_benchmark, verify_benchmark);
criterion_main!(benches);
