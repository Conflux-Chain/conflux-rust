// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[test]
fn test_slice_verifier_zero_or_one_chunk() {
    // Slice empty mpt.
    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    let chunk_size = 1000;

    let mut slicer = MptSlicer::new(&mut snapshot_mpt).unwrap();
    let mut slicer_chunk_bounds = vec![];
    loop {
        slicer.advance(chunk_size).unwrap();
        match slicer.get_range_end_key() {
            Some(key) => {
                slicer_chunk_bounds.push(Vec::from(key));
                println!("{:?}", key);
            }
            None => {
                break;
            }
        }
    }
    assert_eq!(0, slicer_chunk_bounds.len());
    assert!(
        MptSliceVerifier::new(None, &[], None, None, MERKLE_NULL_NODE)
            .restore(&Vec::<Vec<u8>>::new(), &vec![],)
            .map(|result| result.is_valid)
            .unwrap_or(false)
    );

    // Slice mpt with a few key-values
    let number_keys = 20;
    let mut rng = get_rng_for_test();
    let mut keys: Vec<Vec<u8>> = generate_keys(number_keys);
    keys.sort();
    let mpt_kv_iter = DumpedMptKvIterator {
        kv: keys
            .iter()
            .map(|k| {
                (
                    k[..].into(),
                    [&k[..], &k[..], &k[..], &k[..]].concat()
                        [0..(6 + rng.gen::<usize>() % 10)]
                        .into(),
                )
            })
            .collect(),
    };

    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    let merkle_root = MptMerger::new(None, &mut snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let mut slicer = MptSlicer::new(&mut snapshot_mpt).unwrap();
    let mut slicer_chunk_bounds = vec![];
    loop {
        slicer.advance(chunk_size).unwrap();
        match slicer.get_range_end_key() {
            Some(key) => {
                slicer_chunk_bounds.push(Vec::from(key));
                println!("{:?}", key);
            }
            None => {
                break;
            }
        }
    }
    assert_eq!(0, slicer_chunk_bounds.len());
    assert!(MptSliceVerifier::new(None, &[], None, None, merkle_root)
        .restore(
            &mpt_kv_iter.kv.iter().map(|kv| &*kv.0).collect(),
            &mpt_kv_iter.kv.iter().map(|kv| kv.1.to_vec()).collect(),
        )
        .map(|result| result.is_valid)
        .unwrap_or(false));
}

#[test]
fn test_slice_verifier() {
    // Slice big MPT.
    let mut rng = get_rng_for_test();
    let mut keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS)
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();
    keys.sort();
    let mpt_kv_iter = DumpedMptKvIterator {
        kv: keys
            .iter()
            .map(|k| {
                (
                    k[..].into(),
                    [&k[..], &k[..], &k[..], &k[..]].concat()
                        [0..(6 + rng.gen::<usize>() % 10)]
                        .into(),
                )
            })
            .collect(),
    };

    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    let merkle_root = MptMerger::new(None, &mut snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let mut size_sum = Vec::with_capacity(keys.len());
    let mut total_rlp_size = 0;
    for (key, value) in &mpt_kv_iter.kv {
        total_rlp_size += rlp_key_value_len(key.len() as u16, value.len());
        size_sum.push(total_rlp_size);
    }
    let chunk_size = size_sum.last().unwrap() / 5 as u64;

    // Slice by scanning to get chunk contents.
    let mut right_bound = 0;
    let mut start_size = 0;
    let mut right_bounds = vec![];
    let mut chunk_key_bounds = vec![Some(vec![])];
    while right_bound < keys.len() {
        if size_sum[right_bound] > chunk_size + start_size {
            right_bounds.push(right_bound);
            start_size = size_sum[right_bound - 1];
            chunk_key_bounds.push(Some(mpt_kv_iter.kv[right_bound].0.clone()));
        }
        right_bound += 1;
    }
    right_bounds.push(right_bound);
    chunk_key_bounds.push(None);

    // Slice by MptSlicer to get proofs.
    let mut slicer = MptSlicer::new(&mut snapshot_mpt).unwrap();
    let mut slicer_chunk_bounds = vec![];
    let mut slicer_chunk_proofs = vec![];
    loop {
        slicer.advance(chunk_size).unwrap();
        match slicer.get_range_end_key() {
            Some(key) => {
                slicer_chunk_bounds.push(Vec::from(key));
                slicer_chunk_proofs.push(Some(slicer.to_proof()));
            }
            None => {
                break;
            }
        }
    }
    slicer_chunk_proofs.push(None);
    let mut last_proof = None;
    let mut chunk_start_offset = 0;
    for i in 0..slicer_chunk_proofs.len() {
        let chunk_bound = right_bounds[i];
        println!(
            "test chunk {}, chunk range {}..{}, chunk_last_kvs {:?}",
            i,
            chunk_start_offset,
            chunk_bound,
            &mpt_kv_iter.kv[chunk_bound - 3..chunk_bound],
        );
        assert!(MptSliceVerifier::new(
            last_proof,
            &**chunk_key_bounds[i].as_ref().unwrap(),
            slicer_chunk_proofs[i].as_ref(),
            chunk_key_bounds[i + 1].as_ref().map(|v| &**v),
            merkle_root
        )
        .restore(
            &mpt_kv_iter.kv[chunk_start_offset..chunk_bound]
                .iter()
                .map(|kv| &*kv.0)
                .collect(),
            &mpt_kv_iter.kv[chunk_start_offset..chunk_bound]
                .iter()
                .map(|kv| kv.1.to_vec())
                .collect(),
        )
        .map(|result| result.is_valid)
        .unwrap_or(false));
        // Check incomplete chunk.
        for j_omit in [
            (chunk_start_offset..min(chunk_start_offset + 5, chunk_bound))
                .collect::<Vec<usize>>(),
            vec![(chunk_start_offset + chunk_bound) / 2],
            (max(chunk_start_offset, chunk_bound - 5)..chunk_bound)
                .collect::<Vec<usize>>(),
        ]
        .concat()
        {
            println!(
                "test key omit, chunk {}, chunk range {}..{}, omit index {}, kv: {:?},\
                chunk_last_kvs {:?}",
                i, chunk_start_offset, chunk_bound, j_omit, mpt_kv_iter.kv[j_omit],
                &mpt_kv_iter.kv[chunk_bound - 3..chunk_bound],
            );
            let mut keys = Vec::with_capacity(chunk_bound - chunk_start_offset);
            let mut values =
                Vec::with_capacity(chunk_bound - chunk_start_offset);
            for index in chunk_start_offset..chunk_bound {
                if index != j_omit {
                    keys.push(&*mpt_kv_iter.kv[index].0);
                    values.push(mpt_kv_iter.kv[index].1.to_vec());
                }
            }
            assert!(!MptSliceVerifier::new(
                last_proof,
                &**chunk_key_bounds[i].as_ref().unwrap(),
                slicer_chunk_proofs[i].as_ref(),
                chunk_key_bounds[i + 1].as_ref().map(|v| &**v),
                merkle_root,
            )
            .restore(&keys, &values)
            .map(|result| result.is_valid)
            .unwrap_or(false));
        }
        last_proof = slicer_chunk_proofs[i].as_ref();
        chunk_start_offset = chunk_bound;
    }
}

#[derive(Default)]
pub struct FakeSnapshotDb {
    kv: BTreeMap<Vec<u8>, Box<[u8]>>,
    mpt_db: Arc<Mutex<FakeSnapshotMptDb>>,
}

impl FakeSnapshotDb {
    pub fn new(kv: &[(Vec<u8>, Box<[u8]>)], mpt: &FakeSnapshotMptDb) -> Self {
        Self {
            kv: kv.iter().cloned().collect(),
            mpt_db: Arc::new(Mutex::new(mpt.clone())),
        }
    }
}

impl KeyValueDbTypes for Arc<Mutex<FakeSnapshotDb>> {
    type ValueType = Box<[u8]>;
}

impl KeyValueDbTraitOwnedRead for Arc<Mutex<FakeSnapshotDb>> {
    fn get_mut(&mut self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        Ok(self.lock().kv.get(key).cloned())
    }
}

impl KeyValueDbTraitRead for Arc<Mutex<FakeSnapshotDb>> {
    fn get(&self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        Ok(self.lock().kv.get(key).cloned())
    }
}

impl KeyValueDbTraitSingleWriter for Arc<Mutex<FakeSnapshotDb>> {
    fn delete(
        &mut self, key: &[u8],
    ) -> Result<Option<Option<Self::ValueType>>> {
        Ok(Some(self.lock().kv.remove(key)))
    }

    fn put(
        &mut self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        Ok(Some(self.lock().kv.insert(key.into(), value.into())))
    }
}

impl SnapshotDbWriteableTrait for Arc<Mutex<FakeSnapshotDb>> {
    type SnapshotDbBorrowMutType = Arc<Mutex<FakeSnapshotMptDb>>;

    fn start_transaction(&mut self) -> Result<()> { Ok(()) }

    fn commit_transaction(&mut self) -> Result<()> { Ok(()) }

    fn put_kv(
        &mut self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        Ok(Some(self.lock().kv.insert(key.into(), value.into())))
    }

    fn open_snapshot_mpt_owned(
        &mut self,
    ) -> Result<Self::SnapshotDbBorrowMutType> {
        Ok(self.lock().mpt_db.clone())
    }
}

impl SnapshotMptTraitRead for Arc<Mutex<FakeSnapshotMptDb>> {
    fn get_merkle_root(&self) -> MerkleHash { self.lock().get_merkle_root() }

    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>> {
        self.lock().load_node(path)
    }
}

impl SnapshotMptTraitReadAndIterate for Arc<Mutex<FakeSnapshotMptDb>> {
    fn iterate_subtree_trie_nodes_without_root(
        &mut self, _path: &dyn CompressedPathTrait,
    ) -> Result<Box<dyn SnapshotMptIteraterTrait + '_>> {
        // We can't simply forward the call to FakeSnapshotMptDb because
        // lifetime doesn't match.
        unreachable!()
    }
}

impl SnapshotMptTraitRw for Arc<Mutex<FakeSnapshotMptDb>> {
    fn delete_node(&mut self, path: &dyn CompressedPathTrait) -> Result<()> {
        self.lock().delete_node(path)
    }

    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()> {
        self.lock().write_node(path, trie_node)
    }
}

impl WrappedTrait<dyn FallibleIterator<Item = MptKeyValue, Error = Error>>
    for KvdbIterIterator<MptKeyValue, [u8], FakeSnapshotDb>
{
}
impl<'a>
    WrappedLifetimeFamily<
        'a,
        dyn FallibleIterator<Item = MptKeyValue, Error = Error>,
    > for KvdbIterIterator<MptKeyValue, [u8], FakeSnapshotDb>
{
    type Out = DumpedMptKvFallibleIterator;
}

impl KeyValueDbIterableTrait<MptKeyValue, [u8], FakeSnapshotDb>
    for ArcMutexFakeSnapshotDbRef<'_>
{
    fn iter_range(
        &mut self, lower_bound_incl: &[u8], upper_bound_excl: Option<&[u8]>,
    ) -> Result<
        Wrap<
            KvdbIterIterator<(Vec<u8>, Box<[u8]>), [u8], FakeSnapshotDb>,
            dyn FallibleIterator<Item = (Vec<u8>, Box<[u8]>), Error = Error>,
        >,
    > {
        let db = &*self.r.lock();
        Ok(Wrap(DumpedMptKvFallibleIterator {
            kv: db
                .kv
                .range((
                    Included(Vec::from(lower_bound_incl)),
                    upper_bound_excl
                        .map_or(Unbounded, |v| Excluded(Vec::from(v))),
                ))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            index: 0,
        }))
    }

    fn iter_range_excl(
        &mut self, lower_bound_excl: &[u8], upper_bound_excl: &[u8],
    ) -> Result<
        Wrap<
            KvdbIterIterator<(Vec<u8>, Box<[u8]>), [u8], FakeSnapshotDb>,
            dyn FallibleIterator<Item = (Vec<u8>, Box<[u8]>), Error = Error>,
        >,
    > {
        let db = &*self.r.lock();
        Ok(Wrap(DumpedMptKvFallibleIterator {
            kv: db
                .kv
                .range((
                    Excluded(Vec::from(lower_bound_excl)),
                    Excluded(Vec::from(upper_bound_excl)),
                ))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            index: 0,
        }))
    }
}

pub struct ArcMutexFakeSnapshotDbRef<'a> {
    // To work around an annoying rust compilation error because Arc is an
    // upstream type. Rust is afraid that DerefMut is implemented for Arc
    // so that which implementation for KvdbIterImplKind to apply can become
    // ambigiuous.
    r: &'a Arc<Mutex<FakeSnapshotDb>>,
}

impl<'db> OpenSnapshotMptTrait<'db> for Arc<Mutex<FakeSnapshotDb>> {
    type SnapshotDbAsOwnedType = Arc<Mutex<FakeSnapshotMptDb>>;
    type SnapshotDbBorrowMutType = Arc<Mutex<FakeSnapshotMptDb>>;
    type SnapshotDbBorrowSharedType = Arc<Mutex<FakeSnapshotMptDb>>;

    fn open_snapshot_mpt_owned(
        &'db mut self,
    ) -> Result<Self::SnapshotDbBorrowMutType> {
        Ok(self.lock().mpt_db.clone())
    }

    fn open_snapshot_mpt_as_owned(
        &'db self,
    ) -> Result<Self::SnapshotDbAsOwnedType> {
        Ok(self.lock().mpt_db.clone())
    }

    fn open_snapshot_mpt_shared(
        &'db self,
    ) -> Result<Self::SnapshotDbBorrowSharedType> {
        Ok(self.lock().mpt_db.clone())
    }
}

enable_impl_transmute_for_element_satisfy! {
    generic ;
    trait 'static + KeyValueDbIterableTrait<MptKeyValue, [u8], FakeSnapshotDb>;
    for ArcMutexFakeSnapshotDbRef<'_>;
}

impl
    WrappedTrait<dyn KeyValueDbIterableTrait<MptKeyValue, [u8], FakeSnapshotDb>>
    for Arc<Mutex<FakeSnapshotDb>>
{
}

impl<'a>
    WrappedLifetimeFamily<
        'a,
        dyn KeyValueDbIterableTrait<MptKeyValue, [u8], FakeSnapshotDb>,
    > for Arc<Mutex<FakeSnapshotDb>>
{
    type Out = ArcMutexFakeSnapshotDbRef<'a>;
}

impl SnapshotDbTrait for Arc<Mutex<FakeSnapshotDb>> {
    type SnapshotKvdbIterTraitTag = FakeSnapshotDb;
    type SnapshotKvdbIterType = Self;

    fn get_null_snapshot() -> Self { unreachable!() }

    fn open(
        _snapshot_path: &Path, _readonly: bool,
        _already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        _open_semaphore: &Arc<Semaphore>,
    ) -> Result<Self> {
        unreachable!()
    }

    fn create(
        _snapshot_path: &Path,
        _already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        _open_semaphore: &Arc<Semaphore>, _old_version: bool,
    ) -> Result<Self> {
        unreachable!()
    }

    fn direct_merge(
        &mut self, _old_snapshot_db: Option<&Arc<Self>>,
        _mpt_snapshot: &mut Option<SnapshotMptDbSqlite>,
        _recover_mpt_with_kv_snapshot_exist: bool,
        _in_reconstruct_snapshot_state: bool,
    ) -> Result<MerkleHash> {
        unreachable!()
    }

    fn copy_and_merge(
        &mut self, _old_snapshot_db: &Arc<Self>,
        _mpt_snapshot_db: &mut Option<SnapshotMptDbSqlite>,
        _in_reconstruct_snapshot_state: bool,
    ) -> Result<MerkleHash> {
        unreachable!()
    }

    fn start_transaction(&mut self) -> Result<()> { Ok(()) }

    fn commit_transaction(&mut self) -> Result<()> { Ok(()) }

    fn is_mpt_table_in_current_db(&self) -> bool { unreachable!() }

    fn snapshot_kv_iterator(
        &self,
    ) -> Result<
        Wrap<
            Self::SnapshotKvdbIterType,
            dyn KeyValueDbIterableTrait<MptKeyValue, [u8], FakeSnapshotDb>,
        >,
    > {
        Ok(Wrap(ArcMutexFakeSnapshotDbRef { r: self }))
    }
}

#[derive(Default)]
struct FakeSnapshotDbManager {
    temp_snapshot: Arc<Mutex<FakeSnapshotDb>>,
}

impl SnapshotDbManagerTrait for FakeSnapshotDbManager {
    type SnapshotDb = Arc<Mutex<FakeSnapshotDb>>;
    type SnapshotDbWrite = Arc<Mutex<FakeSnapshotDb>>;

    fn get_snapshot_dir(&self) -> &Path { unreachable!() }

    fn get_snapshot_db_name(&self, _snapshot_epoch_id: &EpochId) -> String {
        unreachable!()
    }

    fn get_snapshot_db_path(&self, _snapshot_epoch_id: &EpochId) -> PathBuf {
        unreachable!()
    }

    fn get_mpt_snapshot_dir(&self) -> &Path { unreachable!() }

    fn get_latest_mpt_snapshot_db_name(&self) -> String { unreachable!() }

    fn recovery_latest_mpt_snapshot_from_checkpoint(
        &self, _snapshot_epoch_id: &EpochId,
        _snapshot_epoch_id_before_recovered: Option<EpochId>,
    ) -> Result<()> {
        unreachable!()
    }

    fn create_mpt_snapshot_from_latest(
        &self, _new_snapshot_epoch_id: &EpochId,
    ) -> Result<()> {
        unreachable!()
    }

    fn get_epoch_id_from_snapshot_db_name(
        &self, _snapshot_db_name: &str,
    ) -> Result<EpochId> {
        unreachable!()
    }

    fn try_get_new_snapshot_epoch_from_temp_path(
        &self, _dir_name: &str,
    ) -> Option<EpochId> {
        unreachable!()
    }

    fn try_get_new_snapshot_epoch_from_mpt_temp_path(
        &self, _dir_name: &str,
    ) -> Option<EpochId> {
        unreachable!()
    }

    fn scan_persist_state(
        &self, _snapshot_info_map: &HashMap<EpochId, SnapshotInfo>,
    ) -> Result<SnapshotPersistState> {
        unreachable!()
    }

    fn new_snapshot_by_merging<'m>(
        &self, _old_snapshot_epoch_id: &EpochId, _snapshot_epoch_id: EpochId,
        _delta_mpt: DeltaMptIterator, _in_progress_snapshot_info: SnapshotInfo,
        _snapshot_info_map: &'m RwLock<PersistedSnapshotInfoMap>,
        _new_epoch_height: u64, _recover_mpt_with_kv_snapshot_exist: bool,
    ) -> Result<(RwLockWriteGuard<'m, PersistedSnapshotInfoMap>, SnapshotInfo)>
    {
        unreachable!()
    }

    fn get_snapshot_by_epoch_id(
        &self, _epoch_id: &EpochId, _try_open: bool, _open_mpt_snapshot: bool,
    ) -> Result<Option<Self::SnapshotDb>> {
        unreachable!()
    }

    fn destroy_snapshot(&self, _snapshot_epoch_id: &EpochId) -> Result<()> {
        unreachable!()
    }

    fn new_temp_snapshot_for_full_sync(
        &self, _snapshot_epoch_id: &EpochId, _merkle_root: &EpochId,
        _epoch_height: u64,
    ) -> Result<Self::SnapshotDbWrite> {
        Ok(self.temp_snapshot.clone())
    }

    fn finalize_full_sync_snapshot<'m>(
        &self, _snapshot_epoch_id: &MerkleHash, _merkle_root: &MerkleHash,
        _snapshot_info_map_rwlock: &'m RwLock<PersistedSnapshotInfoMap>,
    ) -> Result<RwLockWriteGuard<'m, PersistedSnapshotInfoMap>> {
        unreachable!()
    }
}

#[test]
fn test_full_sync_verifier_one_chunk() {
    let mut rng = get_rng_for_test();
    let mut keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS);
    keys.sort();
    let mpt_kv_iter = DumpedMptKvIterator {
        kv: keys
            .iter()
            .map(|k| {
                (
                    k[..].into(),
                    [&k[..], &k[..], &k[..], &k[..]].concat()
                        [0..(6 + rng.gen::<usize>() % 10)]
                        .into(),
                )
            })
            .collect(),
    };

    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    let merkle_root = MptMerger::new(None, &mut snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let snapshot_db_manager = FakeSnapshotDbManager::default();

    let mut full_sync_verifier = FullSyncVerifier::new(
        1,
        vec![],
        vec![],
        merkle_root,
        &snapshot_db_manager,
        &NULL_EPOCH,
        0,
    )
    .unwrap();

    let chunk_restored = full_sync_verifier
        .restore_chunk(
            &None,
            &mpt_kv_iter.kv.iter().map(|kv| kv.0.clone()).collect(),
            mpt_kv_iter.kv.iter().map(|kv| kv.1.to_vec()).collect(),
        )
        .unwrap();
    assert!(chunk_restored);

    // Check key-values.
    let temp_snapshot = &*snapshot_db_manager.temp_snapshot.lock();
    assert_eq!(temp_snapshot.kv.len(), mpt_kv_iter.kv.len());
    for (key, value) in &mpt_kv_iter.kv {
        assert_eq!(temp_snapshot.kv.get(key), Some(value));
    }

    // Check MPT key-values and subtree size.
    temp_snapshot.mpt_db.lock().assert_eq(&snapshot_mpt);
}

#[test]
fn test_full_sync_verifier() {
    // Slice big mpt.
    let mut rng = get_rng_for_test();
    let mut keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS)
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();
    keys.sort();
    let mpt_kv_iter = DumpedMptKvIterator {
        kv: keys
            .iter()
            .map(|k| {
                (
                    k[..].into(),
                    [&k[..], &k[..], &k[..], &k[..]].concat()
                        [0..(6 + rng.gen::<usize>() % 10)]
                        .into(),
                )
            })
            .collect(),
    };

    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    let merkle_root = MptMerger::new(None, &mut snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let mut size_sum = Vec::with_capacity(keys.len());
    let mut total_rlp_size = 0;
    for (key, value) in &mpt_kv_iter.kv {
        total_rlp_size += rlp_key_value_len(key.len() as u16, value.len());
        size_sum.push(total_rlp_size);
    }
    let chunk_size = size_sum.last().unwrap() / 5 as u64;

    // Slice by scanning to get chunk contents.
    let mut right_bound = 0;
    let mut start_size = 0;
    let mut right_bounds = vec![];
    while right_bound < keys.len() {
        if size_sum[right_bound] > chunk_size + start_size {
            right_bounds.push(right_bound);
            start_size = size_sum[right_bound - 1];
        }
        right_bound += 1;
    }
    right_bounds.push(right_bound);

    // Slice by MptSlicer to get proofs.
    let mut slicer = MptSlicer::new(&mut snapshot_mpt).unwrap();
    let mut slicer_chunk_bounds = vec![];
    let mut slicer_chunk_proofs = vec![];
    loop {
        slicer.advance(chunk_size).unwrap();
        match slicer.get_range_end_key() {
            Some(key) => {
                slicer_chunk_bounds.push(Vec::from(key));
                slicer_chunk_proofs.push(slicer.to_proof());
            }
            None => {
                break;
            }
        }
    }
    drop(slicer);

    let snapshot_db_manager = FakeSnapshotDbManager::default();

    let mut full_sync_verifier = FullSyncVerifier::new(
        right_bounds.len(),
        slicer_chunk_bounds.clone(),
        slicer_chunk_proofs,
        merkle_root,
        &snapshot_db_manager,
        &NULL_EPOCH,
        0,
    )
    .unwrap();

    let mut chunk_start_offset = 0;
    for i in 0..right_bounds.len() {
        let upper_key = if i < right_bounds.len() - 1 {
            Some(slicer_chunk_bounds[i].clone())
        } else {
            None
        };
        let chunk_restored = full_sync_verifier
            .restore_chunk(
                &upper_key,
                &mpt_kv_iter.kv[chunk_start_offset..right_bounds[i]]
                    .iter()
                    .map(|kv| kv.0.clone())
                    .collect(),
                mpt_kv_iter.kv[chunk_start_offset..right_bounds[i]]
                    .iter()
                    .map(|kv| kv.1.to_vec())
                    .collect(),
            )
            .unwrap();
        chunk_start_offset = right_bounds[i];
        assert!(chunk_restored);
    }

    // Check key-values.
    let temp_snapshot = &*snapshot_db_manager.temp_snapshot.lock();
    assert_eq!(temp_snapshot.kv.len(), mpt_kv_iter.kv.len());
    for (key, value) in &mpt_kv_iter.kv {
        assert_eq!(temp_snapshot.kv.get(key), Some(value));
    }

    // Check MPT key-values and subtree size.
    temp_snapshot.mpt_db.lock().assert_eq(&snapshot_mpt);
}

use crate::{
    impls::{
        errors::*,
        merkle_patricia_trie::{
            mpt_cursor::rlp_key_value_len, CompressedPathTrait, MptMerger,
        },
        snapshot_sync::restoration::{
            full_sync_verifier::FullSyncVerifier,
            mpt_slice_verifier::MptSliceVerifier,
        },
        storage_db::{
            snapshot_db_manager_sqlite::AlreadyOpenSnapshots,
            snapshot_mpt_db_sqlite::SnapshotMptDbSqlite,
        },
        storage_manager::PersistedSnapshotInfoMap,
    },
    storage_db::{
        DbValueType, KeyValueDbIterableTrait, KeyValueDbTraitOwnedRead,
        KeyValueDbTraitRead, KeyValueDbTraitSingleWriter, KeyValueDbTypes,
        KvdbIterIterator, OpenSnapshotMptTrait, SnapshotDbManagerTrait,
        SnapshotDbTrait, SnapshotDbWriteableTrait, SnapshotInfo,
        SnapshotMptIteraterTrait, SnapshotMptNode, SnapshotMptTraitRead,
        SnapshotMptTraitReadAndIterate, SnapshotMptTraitRw,
        SnapshotPersistState,
    },
    tests::{
        generate_keys, get_rng_for_test, snapshot::FakeSnapshotMptDb,
        DumpedMptKvFallibleIterator, DumpedMptKvIterator, TEST_NUMBER_OF_KEYS,
    },
    utils::{
        tuple::ElementSatisfy,
        wrap::{Wrap, WrappedLifetimeFamily, WrappedTrait},
    },
    DeltaMptIterator, MptKeyValue, MptSlicer,
};
use fallible_iterator::FallibleIterator;
use parking_lot::{Mutex, RwLock, RwLockWriteGuard};
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE, NULL_EPOCH};
use rand::Rng;
use std::{
    cmp::{max, min},
    collections::{BTreeMap, HashMap},
    ops::Bound::{Excluded, Included, Unbounded},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio02::sync::Semaphore;
