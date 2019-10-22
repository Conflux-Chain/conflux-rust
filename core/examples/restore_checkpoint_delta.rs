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
        SnapshotAndEpochIdRef,
    },
    sync::{
        delta::{Chunk, ChunkReader, StateDumper},
        restore::Restorer,
        Error,
    },
};
use primitives::{Account, MerkleHash};
use rlp::Rlp;
use std::{
    cmp::min,
    env::current_dir,
    fs::{create_dir_all, remove_dir_all},
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

// cargo run --release -p cfxcore --example restore_checkpoint_delta
fn main() -> Result<(), Error> {
    let test_dir = current_dir()?.join("test_restore_checkpoint_delta");
    if test_dir.exists() {
        remove_dir_all(&test_dir)?;
    }

    // setup node 1
    println!("====================================================");
    println!("Setup node 1 ...");
    let sm1 = new_state_manager(test_dir.join("db1").to_str().unwrap())?;
    let (genesis_hash, genesis_root) = initialize_genesis(&sm1)?;
    let (checkpoint, checkpoint_root) =
        prepare_checkpoint(&sm1, &genesis_hash, 10_000_000)?;
    let chunk_store_dir = test_dir
        .join("state_checkpoints")
        .to_str()
        .unwrap()
        .to_string();
    StateDumper::new(chunk_store_dir.clone(), checkpoint, 4 * 1024 * 1024)
        .dump(&sm1)?;

    // setup node 2
    println!("====================================================");
    println!("Setup node 2 ...");
    let sm2 = new_state_manager(test_dir.join("db2").to_str().unwrap())?;
    let (genesis_hash2, genesis_root2) = initialize_genesis(&sm2)?;
    assert_eq!(genesis_hash, genesis_hash2);
    assert_eq!(genesis_root, genesis_root2);

    // restore chunks for checkpoint
    println!("====================================================");
    println!("sync manifest ...");
    let reader =
        ChunkReader::new(chunk_store_dir.clone(), &checkpoint).unwrap();
    let manifest = reader.chunks()?;
    println!("manifest: {}\n{:#?}", manifest.len(), manifest);

    println!("====================================================");
    println!("sync chunks ...");
    let restore_dir = test_dir
        .join("state_checkpoints_restoration")
        .to_str()
        .unwrap()
        .to_string();
    let restorer = Restorer::new(restore_dir, checkpoint);
    let start = Instant::now();
    for hash in manifest {
        let raw_chunk = reader.chunk_raw(&hash)?.unwrap();
        let chunk = Rlp::new(&raw_chunk).as_val::<Chunk>()?;
        restorer.append(hash, chunk);
    }
    println!("all chunks downloaded in {:?}", start.elapsed());
    println!("current restoration progress: {:?}", restorer.progress());
    println!("begin to restore ...");
    let start = Instant::now();
    restorer.start_to_restore(sm2.clone());
    while !restorer.progress().is_completed() {
        std::thread::sleep(Duration::from_secs(1));
    }
    println!("restoration completed in {:?}", start.elapsed());
    let restored_root = restorer.restored_state_root(sm2.clone()).delta_root;
    println!("restored root: {:?}", restored_root);
    assert_eq!(restored_root, checkpoint_root);

    // validate restoration
    let epoch_id = SnapshotAndEpochIdRef::new(&checkpoint, None);
    let state = sm2.get_state_no_commit(epoch_id)?.unwrap();

    assert_eq!(
        state.get("123".as_bytes())?,
        Some(vec![1, 2, 3].into_boxed_slice())
    );
    assert_eq!(
        state.get("124".as_bytes())?,
        Some(vec![1, 2, 4].into_boxed_slice())
    );
    assert_eq!(
        state.get("234".as_bytes())?,
        Some(vec![2, 3, 4].into_boxed_slice())
    );
    assert_eq!(
        state.get("235".as_bytes())?,
        Some(vec![2, 3, 5].into_boxed_slice())
    );

    Ok(())
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

    state.set("123".as_bytes(), vec![1, 2, 3].into_boxed_slice())?;
    state.set("124".as_bytes(), vec![1, 2, 4].into_boxed_slice())?;

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
    manager: &StateManager, parent: &H256, accounts: usize,
) -> Result<(H256, MerkleHash), Error> {
    let mut state = manager
        .get_state_for_next_epoch(SnapshotAndEpochIdRef::new(parent, None))?
        .unwrap();

    state.set("234".as_bytes(), vec![2, 3, 4].into_boxed_slice())?;
    state.set("235".as_bytes(), vec![2, 3, 5].into_boxed_slice())?;
    state.compute_state_root()?;
    let mut checkpoint = H256::random();
    state.commit(checkpoint)?;

    println!("begin to add {} accounts for checkpoint ...", accounts);
    let start = Instant::now();
    let mut pending = accounts;
    while pending > 0 {
        let n = min(10_000, pending);
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
        .get_state_no_commit(SnapshotAndEpochIdRef::new(&checkpoint, None))?
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
    let epoch_id = SnapshotAndEpochIdRef::new(parent, None);
    let state = manager.get_state_for_next_epoch(epoch_id).unwrap().unwrap();
    let mut state = StateDb::new(state);
    for i in 0..accounts {
        let addr = Address::random();
        let account =
            Account::new_empty_with_balance(&addr, &i.into(), &0.into());
        state.set(&state.account_key(&addr), &account).unwrap();
    }
    let epoch = H256::random();
    state.commit(epoch).unwrap();
    epoch
}
