// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_bytes::Bytes;
use cfx_executor::{
    executive::{ExecutiveContext, TransactOptions},
    machine::{Machine, VmFactory},
    state::State,
};
use cfx_parameters::consensus::TRANSACTION_DEFAULT_EPOCH_BOUND;
use cfx_statedb::StateDb;
use cfx_storage::{state_manager::StateIndex, StorageManagerTrait};
use cfx_types::{H256, U256};
use cfx_vm_types::Env;
use cfxkey::{Generator, KeyPair, Random};
use client::{archive::ArchiveClient, configuration::Configuration};
use criterion::{criterion_group, criterion_main, Criterion};
use parking_lot::{Condvar, Mutex};
use primitives::{
    transaction::native_transaction::NativeTransaction, Action, Transaction,
};
use std::{sync::Arc, time::Duration};

fn txexe_benchmark(c: &mut Criterion) {
    let mut conf = Configuration::default();
    conf.raw_conf.mode = Some("test".to_owned());
    let exit = Arc::new((Mutex::new(false), Condvar::new()));
    let handler = ArchiveClient::start(conf, exit).unwrap();
    let kp = KeyPair::from_secret(
        "46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let receiver_kp = Random.generate().expect("Fail to generate KeyPair.");

    let tx = Transaction::from(NativeTransaction {
        nonce: 0.into(),
        gas_price: U256::from(100u64),
        gas: U256::from(21000u64),
        value: 1.into(),
        action: Action::Call(receiver_kp.address()),
        storage_limit: 0,
        epoch_height: 0,
        chain_id: 1,
        data: Bytes::new(),
    });
    let tx = tx.sign(kp.secret());
    let machine = Machine::new_with_builtin(
        Default::default(),
        VmFactory::new(1024 * 32),
    );
    let env = Env {
        chain_id: machine.params().chain_id_map(0),
        number: 0,
        author: Default::default(),
        timestamp: Default::default(),
        difficulty: Default::default(),
        accumulated_gas_used: U256::zero(),
        gas_limit: tx.gas().clone(),
        last_hash: H256::zero(),
        epoch_height: 0,
        pos_view: None,
        finalized_epoch: None,
        transaction_epoch_bound: TRANSACTION_DEFAULT_EPOCH_BOUND,
        base_gas_price: Default::default(),
        burnt_gas_price: Default::default(),
    };
    let mut group = c.benchmark_group("Execute 1 transaction");
    group
        .bench_function("Execute 1 transaction", move |b| {
            let mut state = State::new(StateDb::new(
                handler
                    .other_components
                    .consensus
                    .data_man
                    .storage_manager
                    .get_state_for_next_epoch(
                        // FIXME: delta height
                        StateIndex::new_for_test_only_delta_mpt(
                            &handler
                                .other_components
                                .consensus
                                .best_block_hash(),
                        ),
                        false,
                    )
                    .unwrap()
                    .unwrap(),
            ))
            .expect("Failed to initialize state");

            let spec = machine.spec(env.number, env.epoch_height);

            b.iter(|| {
                state.clear();
                let ex =
                    ExecutiveContext::new(&mut state, &env, &machine, &spec);
                let options = TransactOptions::default();
                ex.transact(&tx, options).unwrap();
            })
        })
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(10));
}

criterion_group!(benches, txexe_benchmark);
criterion_main!(benches);
