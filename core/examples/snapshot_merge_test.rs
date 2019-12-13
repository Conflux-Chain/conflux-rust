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
use primitives::{
    Account, MerkleHash, StorageKey, MERKLE_NULL_NODE, NULL_EPOCH,
};

use cfxcore::storage::{
    state_manager::{height_to_delta_height, SNAPSHOT_EPOCHS_CAPACITY},
    storage_db::KeyValueDbTraitRead,
    StateRootAuxInfo,
};
use std::{
    cmp::min,
    collections::HashMap,
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
    if snapshot_dir.exists() {
        remove_dir_all(snapshot_dir)?;
    }
    create_dir_all(snapshot_dir)?;

    // setup node 1
    println!("====================================================");
    println!("Setup node 1 ...");
    let state_manager =
        new_state_manager(test_dir.join("db1").to_str().unwrap())?;
    let storage_manager = state_manager.get_storage_manager();
    let snapshot_db_manager = state_manager
        .get_storage_manager()
        .get_snapshot_manager()
        .get_snapshot_db_manager();

    // state1 is only used to build a delta mpt, so the snapshot within it does
    // not matter.
    let mut accounts_map = HashMap::new();
    let (genesis_hash, _) = initialize_genesis(&state_manager)?;
    let accounts = arg_val(&matches, "accounts");
    let accounts_per_epoch = arg_val(&matches, "accounts-per-epoch");
    let aux_info1 = StateRootAuxInfo {
        snapshot_epoch_id: NULL_EPOCH,
        intermediate_epoch_id: NULL_EPOCH,
        maybe_intermediate_mpt_key_padding: None,
        delta_mpt_key_padding: StorageKey::delta_mpt_padding(
            &MERKLE_NULL_NODE,
            &MERKLE_NULL_NODE,
        ),
    };
    let mut height = 0;
    let (snapshot1_epoch, snapshot1_delta_root) = prepare_state(
        &state_manager,
        genesis_hash,
        &mut height,
        accounts,
        accounts_per_epoch,
        &mut accounts_map,
        &aux_info1,
        &aux_info1,
    )?;
    // Force other internal snapshot-related logic to be triggered
    height = SNAPSHOT_EPOCHS_CAPACITY;
    let delta_mpt = storage_manager
        .get_delta_mpt(&NULL_EPOCH)
        .expect("state exists");
    let delta_mpt_root = delta_mpt
        .get_root_node_ref(&snapshot1_delta_root)?
        .expect("root exists");
    let delta_mpt_iterator = DeltaMptIterator {
        mpt: delta_mpt,
        maybe_root_node: Some(delta_mpt_root),
    };

    let info = SnapshotInfo {
        height,
        parent_snapshot_height: 0,
        // This is unknown for now, and we don't care.
        merkle_root: Default::default(),
        parent_snapshot_epoch_id: NULL_EPOCH,
        pivot_chain_parts: vec![snapshot1_epoch],
        serve_one_step_sync: false,
    };
    let snapshot_info1 = snapshot_db_manager.new_snapshot_by_merging(
        &NULL_EPOCH,
        snapshot1_epoch,
        delta_mpt_iterator,
        info,
    )?;
    storage_manager.register_new_snapshot(snapshot_info1.clone());
    println!("After merging: {:?}", snapshot_info1);
    let aux_info2 = StateRootAuxInfo {
        snapshot_epoch_id: NULL_EPOCH,
        intermediate_epoch_id: snapshot1_epoch,
        maybe_intermediate_mpt_key_padding: Some(
            StorageKey::delta_mpt_padding(&MERKLE_NULL_NODE, &MERKLE_NULL_NODE),
        ),
        delta_mpt_key_padding: StorageKey::delta_mpt_padding(
            &MERKLE_NULL_NODE,
            &snapshot1_delta_root,
        ),
    };
    let (snapshot2_epoch, snapshot2_delta_root) = prepare_state(
        &state_manager,
        snapshot1_epoch,
        &mut height,
        accounts,
        accounts_per_epoch,
        &mut accounts_map,
        &aux_info1,
        &aux_info2,
    )?;
    // Force other internal snapshot-related logic to be triggered
    height = 2 * SNAPSHOT_EPOCHS_CAPACITY;
    let delta_mpt = storage_manager
        .get_delta_mpt(&snapshot1_epoch)
        .expect("state exists");
    let delta_mpt_root = delta_mpt
        .get_root_node_ref(&snapshot2_delta_root)?
        .expect("root exists");
    let delta_mpt_iterator = DeltaMptIterator {
        mpt: delta_mpt,
        maybe_root_node: Some(delta_mpt_root),
    };
    let info = SnapshotInfo {
        height,
        parent_snapshot_height: snapshot_info1.height,
        // This is unknown for now, and we don't care.
        merkle_root: Default::default(),
        parent_snapshot_epoch_id: snapshot1_epoch,
        pivot_chain_parts: vec![snapshot2_epoch],
        serve_one_step_sync: false,
    };
    let snapshot_info2 = snapshot_db_manager.new_snapshot_by_merging(
        &snapshot1_epoch,
        snapshot2_epoch,
        delta_mpt_iterator,
        info,
    )?;
    println!(
        "After merging: {:?}, accounts size {}",
        snapshot_info2,
        accounts_map.len()
    );
    storage_manager.register_new_snapshot(snapshot_info2.clone());
    let snapshot2 = snapshot_db_manager
        .get_snapshot_by_epoch_id(&snapshot2_epoch)?
        .expect("exists");
    for (addr, account) in &accounts_map {
        let value: Option<Box<[u8]>> = snapshot2.get(addr.as_bytes())?;
        assert!(value.is_some(), "Address {:?} does not exist", addr);
        let account_bytes = rlp::encode(account);
        let get_bytes = value.unwrap();
        assert_eq!(account_bytes.as_slice(), get_bytes.as_ref());
    }
    // TODO Make snapshot3 to compare the snapshot merkle_root
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
                .default_value("1000"),
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

fn prepare_state(
    manager: &StateManager, parent: H256, height: &mut u64, accounts: usize,
    accounts_per_epoch: usize, account_map: &mut HashMap<Address, Account>,
    old_aux_info: &StateRootAuxInfo, aux_info: &StateRootAuxInfo,
) -> Result<(H256, MerkleHash), Error>
{
    let mut new_account_map = HashMap::new();
    for i in 0..accounts {
        let addr = Address::random();
        let account =
            Account::new_empty_with_balance(&addr, &i.into(), &0.into());
        new_account_map.insert(addr, account);
    }
    println!("begin to add {} accounts for snapshot...", accounts);
    let start = Instant::now();
    let mut epoch_id = parent;
    let mut pending = accounts;
    let mut account_iter = new_account_map.iter();
    while pending > 0 {
        let n = min(accounts_per_epoch, pending);
        let start2 = Instant::now();
        let aux_info_tmp = if height_to_delta_height(*height) == 0 {
            old_aux_info
        } else {
            aux_info
        };
        let state_index =
            StateIndex::new_for_next_epoch(&epoch_id, aux_info_tmp, *height);
        epoch_id =
            add_accounts_and_commit(manager, n, &mut account_iter, state_index);
        *height += 1;
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
        .get_state_no_commit(StateIndex::new_for_readonly(&epoch_id, aux_info))?
        .unwrap()
        .get_state_root()?
        .unwrap()
        .state_root
        .delta_root;
    println!("checkpoint: epoch_id={:?}, root: {:?}", epoch_id, root);
    account_map.extend(new_account_map.into_iter());

    Ok((epoch_id, root))
}

fn add_accounts_and_commit<'a, Iter>(
    manager: &StateManager, accounts: usize, account_map: &mut Iter,
    state_index: StateIndex,
) -> H256
where
    Iter: Iterator<Item = (&'a Address, &'a Account)>,
{
    let state = manager
        .get_state_for_next_epoch(state_index)
        .unwrap()
        .unwrap();
    let mut state = StateDb::new(state);
    for _ in 0..accounts {
        let (addr, account) =
            account_map.next().expect("Caller has checked the size");
        state
            .set(StorageKey::new_account_key(&addr), account)
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
