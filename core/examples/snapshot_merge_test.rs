// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Address, H256};
use cfxcore::{
    db::NUM_COLUMNS,
    statedb::StateDb,
    storage::{
        state::StateTrait,
        state_manager::{
            StateManager, StateManagerTrait, StorageConfiguration,
        },
        storage_db::{SnapshotDbManagerTrait, SnapshotInfo},
        DeltaMptIterator, StateIndex,
    },
    sync::Error,
};
use clap::{App, Arg, ArgMatches};
use log::LevelFilter;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Config, Root},
};
use primitives::{Account, MerkleHash, StorageKey, NULL_EPOCH};
use std::{
    cmp::min,
    fmt::Debug,
    fs::{create_dir_all, remove_dir_all},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Instant,
};

// cargo run --release -p cfxcore --example snapshot_merge_test
// cargo run --release -p cfxcore --example snapshot_merge_test -- --help
fn main() -> Result<(), Error> {
    enable_log();
    let matches = parse_args();

    // setup test directory
    let test_dir: PathBuf = arg_val(&matches, "test-dir");
    if test_dir.exists() {
        remove_dir_all(&test_dir)?;
    }

    // FIXME Parameterize.
    let snapshot_dir = Path::new("./storage_db/snapshot");
    if !snapshot_dir.exists() {
        create_dir_all(snapshot_dir)?;
    }

    // setup node 1
    println!("====================================================");
    println!("Setup node 1 ...");
    let sm1 = new_state_manager(test_dir.join("db1").to_str().unwrap())?;
    let snapshot_db_manager = sm1
        .get_storage_manager()
        .get_snapshot_manager()
        .get_snapshot_db_manager();

    // state1 is only used to build a delta mpt, so the snapshot within it does
    // not matter.
    let (genesis_hash, _) = initialize_genesis(&sm1)?;
    let accounts = arg_val(&matches, "accounts");
    let accounts_per_epoch = arg_val(&matches, "accounts-per-epoch");
    let (checkpoint, checkpoint_root) =
        prepare_checkpoint(&sm1, genesis_hash, accounts, accounts_per_epoch)?;
    let delta_mpt = sm1
        .get_state_for_next_epoch(StateIndex::new_for_test_only_delta_mpt(
            &checkpoint,
        ))?
        .expect("state exists")
        .get_delta_trie();
    let delta_mpt_root = delta_mpt
        .get_root_node_ref(&checkpoint_root)?
        .expect("root exists");
    let delta_mpt_iterator = DeltaMptIterator {
        maybe_mpt: Some(delta_mpt),
        maybe_root_node: Some(delta_mpt_root),
    };
    let info = SnapshotInfo {
        height: 0,
        parent_snapshot_height: 0,
        // This is unknown for now, and we don't care.
        merkle_root: Default::default(),
        parent_snapshot_epoch_id: NULL_EPOCH,
        pivot_chain_parts: vec![],
        serve_one_step_sync: false,
    };
    let snapshot2 = snapshot_db_manager.new_snapshot_by_merging(
        &NULL_EPOCH,
        checkpoint,
        delta_mpt_iterator,
        info,
    )?;
    println!("After merging: {:?}", snapshot2);
    Ok(())
}

fn parse_args<'a>() -> ArgMatches<'a> {
    App::new("restore_checkpoint_delta")
        .arg(
            Arg::with_name("test-dir")
                .long("test-dir")
                .takes_value(true)
                .value_name("PATH")
                .help("Root directory for test")
                .default_value("test_restore_checkpoint_delta"),
        )
        .arg(
            Arg::with_name("accounts")
                .long("accounts")
                .takes_value(true)
                .value_name("NUM")
                .help("Number of accounts in checkpoint")
                .default_value("10000"),
        )
        .arg(
            Arg::with_name("accounts-per-epoch")
                .long("accounts-per-epoch")
                .takes_value(true)
                .value_name("NUM")
                .help("Number of accounts in each epoch")
                .default_value("10000"),
        )
        .arg(
            Arg::with_name("max-chunk-size")
                .long("max-chunk-size")
                .takes_value(true)
                .value_name("NUM")
                .help("Maximum chunk size in bytes")
                .default_value("4000000"),
        )
        .get_matches()
}

fn arg_val<T>(matches: &ArgMatches, arg_name: &str) -> T
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    let val = matches.value_of(arg_name).unwrap();
    T::from_str(val).unwrap()
}

fn new_state_manager(db_dir: &str) -> Result<Arc<StateManager>, Error> {
    create_dir_all(db_dir)?;

    let db_config = db::db_config(
        Path::new(db_dir),
        Some(128),
        db::DatabaseCompactionProfile::default(),
        NUM_COLUMNS.clone(),
        false,
    );
    let db = db::open_database(db_dir, &db_config)?;

    Ok(Arc::new(StateManager::new(
        db,
        StorageConfiguration::default(),
    )))
}

fn initialize_genesis(
    manager: &StateManager,
) -> Result<(H256, MerkleHash), Error> {
    let mut state = manager.get_state_for_genesis_write();

    //    state.set(
    //        StorageKey::AccountKey(b"123"),
    //        vec![1, 2, 3].into_boxed_slice(),
    //    )?;
    //    state.set(
    //        StorageKey::AccountKey(b"124"),
    //        vec![1, 2, 4].into_boxed_slice(),
    //    )?;

    let root = state.compute_state_root()?;
    println!("genesis root: {:?}", root.state_root.delta_root);

    let genesis_hash = H256::from_str(
        "fa4e44bc69cca4cb2ae88a8fd452826faab9e8764e7eed934feede46c98962fa",
    )
    .unwrap();
    state.commit(genesis_hash.clone())?;

    Ok((genesis_hash, root.state_root.delta_root))
}

fn prepare_checkpoint(
    manager: &StateManager, parent: H256, accounts: usize,
    accounts_per_epoch: usize,
) -> Result<(H256, MerkleHash), Error>
{
    println!("begin to add {} accounts for checkpoint ...", accounts);
    let start = Instant::now();
    let mut checkpoint = parent;
    let mut pending = accounts;
    while pending > 0 {
        let n = min(accounts_per_epoch, pending);
        let start2 = Instant::now();
        checkpoint = add_epoch_with_accounts(manager, &checkpoint, n);
        pending -= n;
        let progress = (accounts - pending) * 100 / accounts;
        println!(
            "{} accounts committed, progress = {}%, elapsed = {:?}",
            n,
            progress,
            start2.elapsed()
        );
    }

    println!("all accounts added in {:?}", start.elapsed());

    let root = manager
        // TODO consider snapshot.
        .get_state_no_commit(StateIndex::new_for_test_only_delta_mpt(
            &checkpoint,
        ))?
        .unwrap()
        .get_state_root()?
        .unwrap()
        .state_root
        .delta_root;
    println!("checkpoint root: {:?}", root);

    Ok((checkpoint, root))
}

fn add_epoch_with_accounts(
    manager: &StateManager, parent: &H256, accounts: usize,
) -> H256 {
    let epoch_id = StateIndex::new_for_test_only_delta_mpt(parent);
    let state = manager.get_state_for_next_epoch(epoch_id).unwrap().unwrap();
    let mut state = StateDb::new(state);
    for i in 0..accounts {
        let addr = Address::random();
        let account =
            Account::new_empty_with_balance(&addr, &i.into(), &0.into());
        state
            .set(StorageKey::new_account_key(&addr), &account)
            .unwrap();
    }
    let epoch = H256::random();
    state.commit(epoch).unwrap();
    epoch
}

fn enable_log() {
    let stdout = ConsoleAppender::builder().build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Warn))
        .unwrap();
    log4rs::init_config(config).expect("success");
}
