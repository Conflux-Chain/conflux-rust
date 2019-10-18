// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use cfxcore::{
    db::NUM_COLUMNS,
    storage::{
        state::StateTrait,
        state_manager::{
            StateManager, StateManagerTrait, StorageConfiguration,
        },
        SnapshotAndEpochIdRef,
    },
    sync::{
        delta::{Chunk, ChunkReader, StateDumper},
        Error,
    },
};
use rlp::Rlp;
use std::{
    fs::{create_dir_all, remove_dir_all},
    path::{Path, PathBuf},
    str::FromStr,
};

// cargo run --release -p cfxcore --example restore_checkpoint_delta
fn main() -> Result<(), Error> {
    let test_dir = PathBuf::from("E:\\zzzzzz");
    if test_dir.exists() {
        remove_dir_all(&test_dir)?;
    }

    // setup node 1
    println!("====================================================");
    println!("Setup node 1 ...");
    let sm1 = new_state_manager(test_dir.join("db1").to_str().unwrap())?;
    let genesis_hash = initialize_genesis(&sm1)?;
    let checkpoint = prepare_checkpoint(&sm1, &genesis_hash)?;
    let chunk_store_dir = test_dir
        .join("state_checkpoints")
        .to_str()
        .unwrap()
        .to_string();
    StateDumper::new(chunk_store_dir.clone(), checkpoint, 30).dump(&sm1)?;

    // setup node 2
    println!("====================================================");
    println!("Setup node 2 ...");
    let sm2 = new_state_manager(test_dir.join("db2").to_str().unwrap())?;
    initialize_genesis(&sm2)?;

    // restore chunks for checkpoint
    println!("====================================================");
    println!("Simulate network sync ...");
    let reader =
        ChunkReader::new(chunk_store_dir.clone(), &checkpoint).unwrap();
    let manifest = reader.chunks()?;
    println!("manifest: {:#?}", manifest);

    for hash in manifest {
        let raw_chunk = reader.chunk_raw(&hash)?.unwrap();
        let chunk = Rlp::new(&raw_chunk).as_val::<Chunk>()?;

        let epoch_id = SnapshotAndEpochIdRef::new(&checkpoint, None);
        let mut state = sm2
            .get_state_no_commit(epoch_id)?
            .unwrap_or_else(|| sm2.get_state_for_genesis_write());
        let root = chunk.restore(&mut state, Some(checkpoint))?.unwrap();
        println!("restored root: {:?}", root.state_root.delta_root);
    }
    println!("checkpoint state restoration completed.");

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

fn new_state_manager(db_dir: &str) -> Result<StateManager, Error> {
    create_dir_all(db_dir)?;

    let db_config = db::db_config(
        Path::new(db_dir),
        Some(128),
        db::DatabaseCompactionProfile::default(),
        NUM_COLUMNS.clone(),
        false,
    );
    let db = db::open_database(db_dir, &db_config)?;

    Ok(StateManager::new(db, StorageConfiguration::default()))
}

fn initialize_genesis(manager: &StateManager) -> Result<H256, Error> {
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

    Ok(genesis_hash)
}

fn prepare_checkpoint(
    manager: &StateManager, parent: &H256,
) -> Result<H256, Error> {
    let mut state = manager
        .get_state_for_next_epoch(SnapshotAndEpochIdRef::new(parent, None))?
        .unwrap();

    state.set("234".as_bytes(), vec![2, 3, 4].into_boxed_slice())?;
    state.set("235".as_bytes(), vec![2, 3, 5].into_boxed_slice())?;

    let root = state.compute_state_root()?;
    println!("checkpoint root: {:?}", root.state_root.delta_root);

    let checkpoint = H256::random();
    state.commit(checkpoint)?;

    Ok(checkpoint)
}
