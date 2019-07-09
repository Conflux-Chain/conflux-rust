// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate client;
extern crate parking_lot;
#[macro_use]
extern crate criterion;

use cfx_bytes::Bytes;
use cfx_types::U256;
use cfxcore::{
    executive::Executive,
    machine::new_machine,
    state::State,
    statedb::StateDb,
    storage::state_manager::{SnapshotAndEpochIdRef, StateManagerTrait},
    vm::{Env, Spec},
    vm_factory::VmFactory,
};
use client::{Client, Configuration};
use criterion::Criterion;
use keylib::{Generator, KeyPair, Random};
use parking_lot::{Condvar, Mutex};
use primitives::{Action, Transaction};
use std::sync::Arc;

fn txgen_benchmark(c: &mut Criterion) {
    let mut conf = Configuration::default();
    conf.raw_conf.test_mode = true;
    let exit = Arc::new((Mutex::new(false), Condvar::new()));
    let handler = Client::start(conf, exit.clone()).unwrap();
    c.bench_function("Randomly generate 1 transaction", move |b| {
        b.iter(|| {
            handler.txgen.generate_transaction();
        });
    });
}

fn txexe_benchmark(c: &mut Criterion) {
    let mut conf = Configuration::default();
    conf.raw_conf.test_mode = true;
    let exit = Arc::new((Mutex::new(false), Condvar::new()));
    let handler = Client::start(conf, exit.clone()).unwrap();
    let kp = KeyPair::from_secret(
        "46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let receiver_kp = Random.generate().expect("Fail to generate KeyPair.");

    let tx = Transaction {
        nonce: 0.into(),
        gas_price: U256::from(100u64),
        gas: U256::from(21000u64),
        value: 1.into(),
        action: Action::Call(receiver_kp.address()),
        data: Bytes::new(),
    };
    let tx = tx.sign(kp.secret());
    let machine = new_machine();
    let mut env = Env {
        number: 0, // TODO: replace 0 with correct cardinal number
        author: Default::default(),
        timestamp: Default::default(),
        difficulty: Default::default(),
        gas_used: U256::zero(),
        gas_limit: tx.gas.clone(),
        last_hashes: Arc::new(vec![]),
    };
    let spec = Spec::new_spec();
    c.bench_function("Execute 1 transaction", move |b| {
        let mut state = State::new(
            StateDb::new(
                handler
                    .consensus
                    .data_man
                    .storage_manager
                    .get_state_for_next_epoch(
                        // FIXME: delta height
                        SnapshotAndEpochIdRef::new(
                            &handler.consensus.best_block_hash(),
                            None,
                        ),
                    )
                    .unwrap()
                    .unwrap(),
            ),
            0.into(),
            VmFactory::new(1024 * 32),
        );
        let mut ex = Executive::new(&mut state, &mut env, &machine, &spec);
        b.iter(|| {
            ex.transact(&tx).unwrap();
            ex.state.clear();
        })
    });
}

criterion_group!(benches, txgen_benchmark, txexe_benchmark);
criterion_main!(benches);
