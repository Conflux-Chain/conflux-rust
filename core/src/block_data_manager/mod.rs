// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    cache_config::CacheConfig,
    cache_manager::{CacheId, CacheManager, CacheSize},
    db::{
        COL_BLOCKS, COL_BLOCK_RECEIPTS, COL_EPOCH_SET_HASHES,
        COL_EXECUTION_CONTEXT, COL_MISC, COL_TX_ADDRESS,
    },
    ext_db::SystemDB,
    parameters::consensus::DEFERRED_STATE_EPOCH_COUNT,
    pow::TargetDifficultyManager,
    storage::{
        state_manager::{SnapshotAndEpochIdRef, StateManagerTrait},
        StorageManager,
    },
    verification::VerificationConfig,
};
use byteorder::{ByteOrder, LittleEndian};
use cfx_types::{Bloom, H256};
use kvdb::DBTransaction;
use malloc_size_of::{new_malloc_size_ops, MallocSizeOf};
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use primitives::{
    block::CompactBlock,
    receipt::{
        Receipt, TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING,
        TRANSACTION_OUTCOME_SUCCESS,
    },
    Block, BlockHeader, SignedTransaction, TransactionAddress,
    TransactionWithSignature,
};
use rlp::{DecoderError, Rlp, RlpStream};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use threadpool::ThreadPool;
pub mod block_data_types;
pub mod tx_data_manager;
use crate::block_data_manager::tx_data_manager::TransactionDataManager;
pub use block_data_types::*;

pub const NULLU64: u64 = !0;

const LOCAL_BLOCK_INFO_SUFFIX_BYTE: u8 = 1;
const BLOCK_BODY_SUFFIX_BYTE: u8 = 2;
const EPOCH_EXECUTION_RESULT_SUFFIX_BYTE: u8 = 3;

pub struct BlockDataManager {
    block_headers: RwLock<HashMap<H256, Arc<BlockHeader>>>,
    blocks: RwLock<HashMap<H256, Arc<Block>>>,
    compact_blocks: RwLock<HashMap<H256, CompactBlock>>,
    block_receipts: RwLock<HashMap<H256, BlockReceiptsInfo>>,
    transaction_addresses: RwLock<HashMap<H256, TransactionAddress>>,
    /// Caching for receipts_root and logs_bloom.
    /// It is not deferred, i.e., indexed by the hash of the pivot block
    /// that produces the result when executed.
    /// It is also used for checking whether an epoch has been executed.
    /// It can be updated, i.e., adding new items, in the following cases:
    /// 1) When a new epoch gets executed in normal execution;
    /// 2) After syncing snapshot, we need to update execution commitment
    ///    for pivot blocks around snapshot block based on blaming information;
    /// 3) After recovering block graph from db, update execution commitment
    ///    according to execution info from db;
    /// 4) In BlockDataManager::new(), update execution commitment of true
    ///    genesis block if it is the current era genesis in BlockDataManager.
    epoch_execution_commitments:
        RwLock<HashMap<H256, EpochExecutionCommitments>>,
    epoch_execution_contexts: RwLock<HashMap<H256, EpochExecutionContext>>,
    invalid_block_set: RwLock<HashSet<H256>>,
    cur_consensus_era_genesis_hash: RwLock<H256>,
    cur_consensus_era_stable_hash: RwLock<H256>,
    instance_id: Mutex<u64>,

    config: DataManagerConfiguration,

    tx_data_manager: TransactionDataManager,

    pub genesis_block: Arc<Block>,
    pub true_genesis_block: Arc<Block>,
    pub db: Arc<SystemDB>,
    pub storage_manager: Arc<StorageManager>,
    cache_man: Arc<Mutex<CacheManager<CacheId>>>,
    pub target_difficulty_manager: TargetDifficultyManager,
}

impl BlockDataManager {
    pub fn new(
        cache_conf: CacheConfig, genesis_block: Arc<Block>, db: Arc<SystemDB>,
        storage_manager: Arc<StorageManager>,
        worker_pool: Arc<Mutex<ThreadPool>>, config: DataManagerConfiguration,
    ) -> Self
    {
        let genesis_hash = genesis_block.block_header.hash();
        let mb = 1024 * 1024;
        let max_cache_size = cache_conf.ledger_mb() * mb;
        let pref_cache_size = max_cache_size * 3 / 4;
        let cache_man = Arc::new(Mutex::new(CacheManager::new(
            pref_cache_size,
            max_cache_size,
            3 * mb,
        )));
        let tx_data_manager =
            TransactionDataManager::new(config.tx_cache_count, worker_pool);

        let mut data_man = Self {
            block_headers: RwLock::new(HashMap::new()),
            blocks: RwLock::new(HashMap::new()),
            compact_blocks: Default::default(),
            block_receipts: Default::default(),
            transaction_addresses: Default::default(),
            epoch_execution_commitments: Default::default(),
            epoch_execution_contexts: Default::default(),
            invalid_block_set: Default::default(),
            genesis_block: genesis_block.clone(),
            true_genesis_block: genesis_block.clone(),
            db,
            storage_manager,
            cache_man,
            instance_id: Mutex::new(0),
            config,
            target_difficulty_manager: TargetDifficultyManager::new(),
            cur_consensus_era_genesis_hash: RwLock::new(genesis_hash),
            cur_consensus_era_stable_hash: RwLock::new(genesis_hash),
            tx_data_manager,
        };

        data_man.initialize_instance_id();

        if let Some((checkpoint_hash, stable_hash)) =
            data_man.checkpoint_hashes_from_db()
        {
            if checkpoint_hash != genesis_block.block_header.hash() {
                if let Some(checkpoint_block) = data_man.block_by_hash(
                    &checkpoint_hash,
                    false, /* update_cache */
                ) {
                    if data_man
                        .storage_manager
                        .contains_state(SnapshotAndEpochIdRef::new(
                            &checkpoint_hash,
                            None,
                        ))
                        .unwrap()
                    {
                        let mut cur_hash =
                            *checkpoint_block.block_header.parent_hash();
                        for _ in 0..DEFERRED_STATE_EPOCH_COUNT - 1 {
                            assert_ne!(cur_hash, H256::default());
                            let cur_block = data_man.block_by_hash(
                                &cur_hash, false, /* update_cache */
                            );
                            if cur_block.is_some()
                                && data_man
                                    .storage_manager
                                    .contains_state(SnapshotAndEpochIdRef::new(
                                        &cur_hash, None,
                                    ))
                                    .unwrap()
                            {
                                let cur_block = cur_block.unwrap();
                                cur_hash =
                                    *cur_block.block_header.parent_hash();
                            } else {
                                panic!("recovery checkpoint from disk failed.");
                            }
                        }

                        *data_man.cur_consensus_era_genesis_hash.write() =
                            checkpoint_hash;
                        *data_man.cur_consensus_era_stable_hash.write() =
                            stable_hash;
                        data_man.genesis_block = checkpoint_block;
                    }
                }
            }
        }

        data_man.insert_epoch_execution_context(
            data_man.genesis_block.hash(),
            EpochExecutionContext {
                start_block_number: 0,
            },
        );

        data_man
            .insert_block(data_man.genesis_block(), true /* persistent */);

        if data_man.genesis_block().hash() == genesis_block.hash() {
            // persist local_block_info for true genesis
            data_man.insert_local_block_info_to_db(
                &genesis_block.hash(),
                LocalBlockInfo::new(
                    BlockStatus::Valid,
                    0,
                    data_man.get_instance_id(),
                ),
            );
            data_man.insert_epoch_execution_commitments(
                data_man.genesis_block.hash(),
                *data_man.genesis_block.block_header.deferred_receipts_root(),
                *data_man
                    .genesis_block
                    .block_header
                    .deferred_logs_bloom_hash(),
            );
        } else {
            // for other era genesis, we need to change the instance_id
            if let Some(mut local_block_info) = data_man
                .local_block_info_from_db(&data_man.genesis_block().hash())
            {
                local_block_info.instance_id = data_man.get_instance_id();
                data_man.insert_local_block_info_to_db(
                    &data_man.genesis_block().hash(),
                    local_block_info,
                );
            }
        }

        data_man
    }

    pub fn get_instance_id(&self) -> u64 { *self.instance_id.lock() }

    pub fn initialize_instance_id(&self) {
        let mut my_instance_id = self.instance_id.lock();
        if *my_instance_id == 0 {
            // load last instance id
            let instance_id = match self.db.key_value().get(COL_MISC, b"instance")
                .expect("Low-level database error when fetching instance id. Some issue with disk?")
                {
                    Some(instance) => {
                        let rlp = Rlp::new(&instance);
                        Some(rlp.val_at::<u64>(0).expect("Failed to decode instance id!"))
                    }
                    None => {
                        info!("No instance id got from db");
                        None
                    }
                };

            // set new instance id
            if let Some(instance_id) = instance_id {
                *my_instance_id = instance_id + 1;
            }
        } else {
            // This case will only happen when full node begins to sync block
            // bodies. And we should change the instance_id of genesis block to
            // current one.
            *my_instance_id += 1;
            if let Some(mut local_block_info) =
                self.local_block_info_from_db(&self.genesis_block().hash())
            {
                local_block_info.instance_id = *my_instance_id;
                self.insert_local_block_info_to_db(
                    &self.genesis_block().hash(),
                    local_block_info,
                );
            }
        }

        // persist new instance id
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(1);
        rlp_stream.append(&(*my_instance_id));
        let mut dbops = self.db.key_value().transaction();
        dbops.put(COL_MISC, b"instance", &rlp_stream.drain());
        self.commit_db_transaction(dbops);
    }

    pub fn genesis_block(&self) -> Arc<Block> { self.genesis_block.clone() }

    pub fn transaction_by_hash(
        &self, hash: &H256,
    ) -> Option<Arc<SignedTransaction>> {
        let address = self
            .transaction_address_by_hash(hash, false /* update_cache */)?;
        let block = self.block_by_hash(
            &address.block_hash,
            false, /* update_cache */
        )?;
        assert!(address.index < block.transactions.len());
        Some(block.transactions[address.index].clone())
    }

    fn commit_db_transaction(&self, transaction: DBTransaction) {
        self.db
            .key_value()
            .write(transaction)
            .expect("crash for db failure");
    }

    fn block_header_from_db(&self, hash: &H256) -> Option<BlockHeader> {
        let rlp_bytes = self.db.key_value().get(COL_BLOCKS, hash)
            .expect("Low level database error when fetching block. Some issue with disk?")?;
        let rlp = Rlp::new(&rlp_bytes);
        let mut block_header = rlp.as_val().expect("Wrong block rlp format!");
        VerificationConfig::compute_header_pow_quality(&mut block_header);
        Some(block_header)
    }

    fn insert_block_header_to_db(&self, header: &BlockHeader) {
        let mut dbops = self.db.key_value().transaction();
        dbops.put(COL_BLOCKS, &header.hash(), &rlp::encode(header));
        self.commit_db_transaction(dbops);
    }

    fn remove_block_header_from_db(&self, hash: &H256) {
        let mut dbops = self.db.key_value().transaction();
        dbops.delete(COL_BLOCKS, hash);
        self.commit_db_transaction(dbops);
    }

    fn block_body_key(block_hash: &H256) -> Vec<u8> {
        let mut key = Vec::with_capacity(block_hash.len() + 1);
        key.extend_from_slice(&block_hash);
        key.push(BLOCK_BODY_SUFFIX_BYTE);
        key
    }

    fn epoch_execution_result_key(hash: &H256) -> Vec<u8> {
        let mut key = Vec::with_capacity(hash.len() + 1);
        key.extend_from_slice(&hash);
        key.push(EPOCH_EXECUTION_RESULT_SUFFIX_BYTE);
        key
    }

    fn block_body_from_db(
        &self, block_hash: &H256,
    ) -> Option<Vec<Arc<SignedTransaction>>> {
        let rlp_bytes = self.db.key_value().get(COL_BLOCKS, &Self::block_body_key(block_hash))
            .expect("Low level database error when fetching block. Some issue with disk?")?;
        let rlp = Rlp::new(&rlp_bytes);
        let block_body = Block::decode_body_with_tx_public(&rlp)
            .expect("Wrong block rlp format!");
        Some(block_body)
    }

    pub fn insert_checkpoint_hashes_to_db(
        &self, checkpoint_prev: &H256, checkpoint_cur: &H256,
    ) {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(2);
        rlp_stream.append(checkpoint_prev);
        rlp_stream.append(checkpoint_cur);
        let mut dbops = self.db.key_value().transaction();
        dbops.put(COL_MISC, b"checkpoint", &rlp_stream.drain());
        self.commit_db_transaction(dbops);
    }

    pub fn checkpoint_hashes_from_db(&self) -> Option<(H256, H256)> {
        match self.db.key_value().get(COL_MISC, b"checkpoint")
            .expect("Low-level database error when fetching 'checkpoint' block. Some issue with disk?")
            {
                Some(checkpoint) => {
                    let rlp = Rlp::new(&checkpoint);
                    Some((rlp.val_at::<H256>(0).expect("Failed to decode checkpoint hash!"),
                          rlp.val_at::<H256>(1).expect("Failed to decode checkpoint hash!")))
                }
                None => {
                    info!("No checkpoint got from db");
                    None
                }
            }
    }

    pub fn insert_epoch_set_hashes_to_db(
        &self, epoch: u64, hashes: &Vec<H256>,
    ) {
        debug!(
            "insert_epoch_set_hashes_to_db: epoch={}, hashes={:?}",
            epoch, hashes
        );
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(hashes.len());
        for hash in hashes {
            rlp_stream.append(hash);
        }
        let mut epoch_key = [0; 8];
        LittleEndian::write_u64(&mut epoch_key[0..8], epoch);
        let mut dbops = self.db.key_value().transaction();
        dbops.put(COL_EPOCH_SET_HASHES, &epoch_key[0..8], &rlp_stream.drain());
        self.commit_db_transaction(dbops);
    }

    pub fn epoch_set_hashes_from_db(&self, epoch: u64) -> Option<Vec<H256>> {
        let mut epoch_key = [0; 8];
        LittleEndian::write_u64(&mut epoch_key[0..8], epoch);
        match self.db.key_value().get(COL_EPOCH_SET_HASHES, &epoch_key[0..8])
            .expect("Low-level database error when fetching 'epoch set hashes'. Some issue with disk?")
            {
                Some(hashes) => {
                    let rlp = Rlp::new(&hashes);
                    Some(rlp.as_list::<H256>().expect("Failed to decode epoch set hashes!"))
                }
                None => {
                    info!("No epoch set hashes got from db, epoch={}", epoch);
                    None
                }
            }
    }

    pub fn insert_terminals_to_db(&self, terminals: &Vec<H256>) {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(terminals.len());
        for hash in terminals {
            rlp_stream.append(hash);
        }
        let mut dbops = self.db.key_value().transaction();
        dbops.put(COL_MISC, b"terminals", &rlp_stream.drain());
        self.commit_db_transaction(dbops);
    }

    pub fn terminals_from_db(&self) -> Option<Vec<H256>> {
        match self.db.key_value().get(COL_MISC, b"terminals")
            .expect("Low-level database error when fetching 'terminals' block. Some issue with disk?")
            {
                Some(terminals) => {
                    let rlp = Rlp::new(&terminals);
                    Some(rlp.as_list::<H256>().expect("Failed to decode terminals!"))
                }
                None => {
                    info!("No terminals got from db");
                    None
                }
            }
    }

    /// insert block body in memory cache and db
    pub fn insert_block_body(
        &self, hash: H256, block: Arc<Block>, persistent: bool,
    ) {
        if persistent {
            self.insert_block_body_to_db(&block);
        }
        self.cache_man.lock().note_used(CacheId::Block(hash));
        self.blocks.write().insert(hash, block);
    }

    fn insert_block_body_to_db(&self, block: &Block) {
        let mut dbops = self.db.key_value().transaction();
        dbops.put(
            COL_BLOCKS,
            &Self::block_body_key(&block.hash()),
            &block.encode_body_with_tx_public(),
        );
        self.commit_db_transaction(dbops);
    }

    fn remove_block_body_from_db(&self, hash: &H256) {
        let mut dbops = self.db.key_value().transaction();
        dbops.delete(COL_BLOCKS, &Self::block_body_key(hash));
        self.commit_db_transaction(dbops);
    }

    /// remove block body in memory cache and db
    pub fn remove_block_body(&self, hash: &H256, remove_db: bool) {
        if remove_db {
            self.remove_block_body_from_db(hash);
        }
        self.blocks.write().remove(hash);
    }

    pub fn block_by_hash(
        &self, hash: &H256, update_cache: bool,
    ) -> Option<Arc<Block>> {
        // Check cache first
        {
            let read = self.blocks.read();
            if let Some(v) = read.get(hash) {
                return Some(v.clone());
            }
        }

        let header = self.block_header_by_hash(hash)?;
        let block = Arc::new(Block {
            block_header: header.as_ref().clone(),
            transactions: self.block_body_from_db(hash)?,
            approximated_rlp_size: 0,
            approximated_rlp_size_with_public: 0,
        });

        if update_cache {
            let mut write = self.blocks.write();
            write.insert(*hash, block.clone());
            self.cache_man.lock().note_used(CacheId::Block(*hash));
        }
        Some(block)
    }

    pub fn block_from_db(&self, block_hash: &H256) -> Option<Block> {
        Some(Block::new(
            self.block_header_from_db(block_hash)?,
            self.block_body_from_db(block_hash)?,
        ))
    }

    pub fn blocks_by_hash_list(
        &self, hashes: &Vec<H256>, update_cache: bool,
    ) -> Option<Vec<Arc<Block>>> {
        let mut blocks = Vec::new();
        for h in hashes {
            blocks.push(self.block_by_hash(h, update_cache)?);
        }
        Some(blocks)
    }

    /// insert block/header into memory cache, block/header into db
    pub fn insert_block(&self, block: Arc<Block>, persistent: bool) {
        let hash = block.hash();
        self.insert_block_header(
            hash,
            Arc::new(block.block_header.clone()),
            persistent,
        );
        self.insert_block_body(hash, block, persistent);
    }

    fn local_block_info_key(block_hash: &H256) -> Vec<u8> {
        let mut key = Vec::with_capacity(block_hash.len() + 1);
        key.extend_from_slice(block_hash);
        key.push(LOCAL_BLOCK_INFO_SUFFIX_BYTE);
        key
    }

    /// Store block info to db. Block info includes block status and
    /// the sequence number when the block enters consensus graph.
    /// The db key is the block hash plus one extra byte, so we can get better
    /// data locality if we get both a block and its info from db.
    /// The info is not a part of the block because the block is inserted
    /// before we know its info, and we do not want to insert a large chunk
    /// again. TODO Maybe we can use in-place modification (operator `merge`
    /// in rocksdb) to keep the info together with the block.
    pub fn insert_local_block_info_to_db(
        &self, block_hash: &H256, block_info: LocalBlockInfo,
    ) {
        let mut dbops = self.db.key_value().transaction();
        dbops.put(
            COL_BLOCKS,
            &Self::local_block_info_key(block_hash),
            &rlp::encode(&block_info),
        );
        self.commit_db_transaction(dbops);
    }

    /// Get block info from db.
    pub fn local_block_info_from_db(
        &self, block_hash: &H256,
    ) -> Option<LocalBlockInfo> {
        self.db
            .key_value()
            .get(COL_BLOCKS, &Self::local_block_info_key(block_hash))
            .expect("crash for db failure")
            .map(|encoded| {
                let rlp = Rlp::new(&encoded);
                rlp.as_val().expect("Wrong block info rlp format!")
            })
    }

    /// remove block body and block header in memory cache and db
    pub fn remove_block(&self, hash: &H256, remove_db: bool) {
        self.remove_block_header(hash, remove_db);
        self.remove_block_body(hash, remove_db);
    }

    pub fn block_header_by_hash(
        &self, hash: &H256,
    ) -> Option<Arc<BlockHeader>> {
        let block_headers = self.block_headers.upgradable_read();
        if let Some(header) = block_headers.get(hash) {
            return Some(header.clone());
        } else if !self.config.persist_header {
            return None;
        } else {
            let maybe_header = self.block_header_from_db(hash);
            maybe_header.map(|header| {
                let header_arc = Arc::new(header);
                RwLockUpgradableReadGuard::upgrade(block_headers)
                    .insert(header_arc.hash(), header_arc.clone());
                self.cache_man
                    .lock()
                    .note_used(CacheId::BlockHeader(header_arc.hash()));
                header_arc
            })
        }
    }

    pub fn insert_block_header(
        &self, hash: H256, header: Arc<BlockHeader>, persistent: bool,
    ) {
        if persistent {
            self.insert_block_header_to_db(&header);
        }
        self.cache_man.lock().note_used(CacheId::BlockHeader(hash));
        self.block_headers.write().insert(hash, header);
    }

    /// remove block header in memory cache and db
    pub fn remove_block_header(&self, hash: &H256, remove_db: bool) {
        if remove_db {
            self.remove_block_header_from_db(hash);
        }
        self.block_headers.write().remove(hash);
    }

    pub fn block_height_by_hash(&self, hash: &H256) -> Option<u64> {
        let result = self.block_by_hash(hash, false /* update_cache */)?;
        Some(result.block_header.height())
    }

    pub fn compact_block_by_hash(&self, hash: &H256) -> Option<CompactBlock> {
        self.compact_blocks.read().get(hash).map(|b| {
            self.cache_man
                .lock()
                .note_used(CacheId::CompactBlock(b.hash()));
            b.clone()
        })
    }

    pub fn insert_compact_block(&self, cb: CompactBlock) {
        let hash = cb.hash();
        self.compact_blocks.write().insert(hash, cb);
        self.cache_man.lock().note_used(CacheId::CompactBlock(hash));
    }

    pub fn contains_compact_block(&self, hash: &H256) -> bool {
        self.compact_blocks.read().contains_key(hash)
    }

    pub fn block_results_by_hash_from_db(
        &self, hash: &H256,
    ) -> Option<(H256, BlockExecutedResult)> {
        trace!("Read receipts from db {}", hash);
        let block_receipts = self.db.key_value().get(COL_BLOCK_RECEIPTS, hash)
            .expect("Low level database error when fetching block receipts. Some issue with disk?")?;
        let rlp = Rlp::new(&block_receipts);
        let epoch: H256 = rlp.val_at(0).expect("encoded");
        let receipts: Vec<Receipt> = rlp.list_at(1).expect("encoded");
        let bloom: Bloom = rlp.val_at(2).expect("encoded");
        Some((
            epoch,
            BlockExecutedResult {
                receipts: Arc::new(receipts),
                bloom,
            },
        ))
    }

    /// Return None if receipts for corresponding epoch is not computed before
    /// or has been overwritten by another new pivot chain in db
    ///
    /// This function will require lock of block_receipts
    pub fn block_results_by_hash_with_epoch(
        &self, hash: &H256, assumed_epoch: &H256, update_cache: bool,
    ) -> Option<BlockExecutedResult> {
        let maybe_receipts =
            self.block_receipts
                .read()
                .get(hash)
                .and_then(|receipt_info| {
                    receipt_info.get_receipts_at_epoch(assumed_epoch)
                });
        if maybe_receipts.is_some() {
            return maybe_receipts;
        }
        let (epoch, receipts) = self.block_results_by_hash_from_db(hash)?;
        if epoch != *assumed_epoch {
            debug!(
                "epoch from db {} does not match assumed {}",
                epoch, assumed_epoch
            );
            return None;
        }
        if update_cache {
            self.block_receipts
                .write()
                .entry(*hash)
                .or_insert(BlockReceiptsInfo::default())
                .insert_receipts_at_epoch(assumed_epoch, receipts.clone());
            self.cache_man
                .lock()
                .note_used(CacheId::BlockReceipts(*hash));
        }
        Some(receipts)
    }

    pub fn insert_block_results(
        &self, hash: H256, epoch: H256, receipts: Arc<Vec<Receipt>>,
        persistent: bool,
    )
    {
        let bloom = receipts.iter().fold(Bloom::zero(), |mut b, r| {
            b.accrue_bloom(&r.log_bloom);
            b
        });

        if persistent {
            let mut dbops = self.db.key_value().transaction();
            let mut rlp_stream = RlpStream::new_list(3);
            rlp_stream.append(&epoch);
            rlp_stream.append_list(&receipts);
            rlp_stream.append(&bloom);
            dbops.put(COL_BLOCK_RECEIPTS, &hash, &rlp_stream.drain());
            self.commit_db_transaction(dbops);
        }

        let mut block_receipts = self.block_receipts.write();
        let receipt_info = block_receipts
            .entry(hash)
            .or_insert(BlockReceiptsInfo::default());
        receipt_info.insert_receipts_at_epoch(
            &epoch,
            BlockExecutedResult { receipts, bloom },
        );

        self.cache_man
            .lock()
            .note_used(CacheId::BlockReceipts(hash));
    }

    pub fn transaction_address_by_hash_from_db(
        &self, hash: &H256,
    ) -> Option<TransactionAddress> {
        let tx_index_encoded = self.db.key_value().get(COL_TX_ADDRESS, hash).expect("Low level database error when fetching transaction index. Some issue with disk?")?;
        let rlp = Rlp::new(&tx_index_encoded);
        let tx_index: TransactionAddress =
            rlp.as_val().expect("Wrong tx index rlp format!");
        Some(tx_index)
    }

    pub fn transaction_address_by_hash(
        &self, hash: &H256, update_cache: bool,
    ) -> Option<TransactionAddress> {
        let transaction_addresses =
            self.transaction_addresses.upgradable_read();
        if let Some(index) = transaction_addresses.get(hash) {
            return Some(index.clone());
        }
        self.transaction_address_by_hash_from_db(hash)
            .map(|address| {
                if update_cache {
                    RwLockUpgradableReadGuard::upgrade(transaction_addresses)
                        .insert(*hash, address.clone());
                    self.cache_man
                        .lock()
                        .note_used(CacheId::TransactionAddress(*hash));
                }
                address
            })
    }

    pub fn insert_transaction_address(
        &self, hash: &H256, tx_address: &TransactionAddress,
    ) {
        if !self.config.record_tx_address {
            return;
        }
        self.transaction_addresses
            .write()
            .entry(*hash)
            .and_modify(|v| {
                *v = tx_address.clone();
                self.cache_man
                    .lock()
                    .note_used(CacheId::TransactionAddress(*hash));
            });
        let mut dbops = self.db.key_value().transaction();
        dbops.put(COL_TX_ADDRESS, hash, &rlp::encode(tx_address));
        self.commit_db_transaction(dbops);
    }

    /// Return `false` if there is no executed results for given `block_hash`
    pub fn receipts_retain_epoch(
        &self, block_hash: &H256, epoch: &H256,
    ) -> bool {
        match self.block_receipts.write().get_mut(block_hash) {
            Some(r) => {
                r.retain_epoch(epoch);
                true
            }
            None => false,
        }
    }

    pub fn insert_epoch_execution_commitments(
        &self, block_hash: H256, receipts_root: H256, logs_bloom_hash: H256,
    ) {
        self.epoch_execution_commitments.write().insert(
            block_hash,
            EpochExecutionCommitments {
                receipts_root,
                logs_bloom_hash,
            },
        );
    }

    pub fn insert_epoch_execution_context(
        &self, hash: H256, ctx: EpochExecutionContext,
    ) {
        self.epoch_execution_contexts.write().insert(hash, ctx);
    }

    pub fn get_epoch_execution_commitments(
        &self, block_hash: &H256,
    ) -> Option<EpochExecutionCommitments> {
        self.epoch_execution_commitments
            .read()
            .get(block_hash)
            .map(Clone::clone)
    }

    pub fn get_epoch_execution_context(
        &self, hash: &H256,
    ) -> Option<EpochExecutionContext> {
        self.epoch_execution_contexts
            .read()
            .get(hash)
            .map(Clone::clone)
    }

    pub fn remove_epoch_execution_commitments(&self, block_hash: &H256) {
        self.epoch_execution_commitments.write().remove(block_hash);
    }

    pub fn remove_epoch_execution_context(&self, block_hash: &H256) {
        self.epoch_execution_contexts.write().remove(block_hash);
    }

    pub fn epoch_executed(&self, epoch_hash: &H256) -> bool {
        // `block_receipts_root` is not computed when recovering from db
        self.get_epoch_execution_commitments(epoch_hash).is_some()
            && self
                .storage_manager
                .contains_state(SnapshotAndEpochIdRef::new(epoch_hash, None))
                .unwrap()
    }

    /// Check if all executed results of an epoch exist
    pub fn epoch_executed_and_recovered(
        &self, epoch_hash: &H256, epoch_block_hashes: &Vec<H256>,
        on_local_pivot: bool,
    ) -> bool
    {
        if !self.epoch_executed(epoch_hash) {
            return false;
        }

        if self.config.record_tx_address && on_local_pivot {
            // Check if all blocks receipts are from this epoch
            let mut epoch_receipts = Vec::new();
            for h in epoch_block_hashes {
                if let Some(r) = self.block_results_by_hash_with_epoch(
                    h, epoch_hash, true, /* update_cache */
                ) {
                    epoch_receipts.push(r.receipts);
                } else {
                    return false;
                }
            }
            // Recover tx address if we will skip pivot chain execution
            for (block_idx, block_hash) in epoch_block_hashes.iter().enumerate()
            {
                let block = self
                    .block_by_hash(block_hash, true /* update_cache */)
                    .expect("block exists");
                for (tx_idx, tx) in block.transactions.iter().enumerate() {
                    match epoch_receipts[block_idx]
                        .get(tx_idx)
                        .unwrap()
                        .outcome_status
                    {
                        TRANSACTION_OUTCOME_SUCCESS
                        | TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING => {
                            self.insert_transaction_address(
                                &tx.hash,
                                &TransactionAddress {
                                    block_hash: *block_hash,
                                    index: tx_idx,
                                },
                            )
                        }
                        _ => {}
                    }
                }
            }
        }
        true
    }

    pub fn invalidate_block(&self, block_hash: H256) {
        // This block will never enter consensus graph, so
        // assign it a NULL sequence number.
        let block_info =
            LocalBlockInfo::new(BlockStatus::Invalid, NULLU64, NULLU64);
        self.insert_local_block_info_to_db(&block_hash, block_info);
        self.invalid_block_set.write().insert(block_hash);
    }

    /// Check if a block is already marked as invalid.
    pub fn verified_invalid(&self, block_hash: &H256) -> bool {
        let invalid_block_set = self.invalid_block_set.upgradable_read();
        if invalid_block_set.contains(block_hash) {
            return true;
        } else {
            if let Some(block_info) = self.local_block_info_from_db(block_hash)
            {
                match block_info.get_status() {
                    BlockStatus::Invalid => {
                        RwLockUpgradableReadGuard::upgrade(invalid_block_set)
                            .insert(*block_hash);
                        return true;
                    }
                    _ => return false,
                }
            } else {
                // No status on disk, so the block is not marked invalid before
                return false;
            }
        }
    }

    pub fn cached_block_count(&self) -> usize { self.blocks.read().len() }

    /// Get current cache size.
    pub fn cache_size(&self) -> CacheSize {
        let malloc_ops = &mut new_malloc_size_ops();
        let block_headers = self.block_headers.read().size_of(malloc_ops);
        let blocks = self.blocks.read().size_of(malloc_ops);
        let compact_blocks = self.compact_blocks.read().size_of(malloc_ops);
        let block_receipts = self.block_receipts.read().size_of(malloc_ops);
        let transaction_addresses =
            self.transaction_addresses.read().size_of(malloc_ops);
        CacheSize {
            block_headers,
            blocks,
            block_receipts,
            transaction_addresses,
            compact_blocks,
        }
    }

    fn block_cache_gc(&self) {
        let malloc_ops = &mut new_malloc_size_ops();
        let current_size = self.cache_size().total();
        let mut block_headers = self.block_headers.write();
        let mut blocks = self.blocks.write();
        let mut compact_blocks = self.compact_blocks.write();
        let mut executed_results = self.block_receipts.write();
        let mut tx_address = self.transaction_addresses.write();
        let mut exeuction_contexts = self.epoch_execution_contexts.write();
        let mut cache_man = self.cache_man.lock();
        info!(
            "Before gc cache_size={} {} {} {} {}",
            current_size,
            blocks.len(),
            compact_blocks.len(),
            executed_results.len(),
            tx_address.len(),
        );

        cache_man.collect_garbage(current_size, |ids| {
            for id in &ids {
                match *id {
                    CacheId::Block(ref h) => {
                        blocks.remove(h);
                    }
                    CacheId::BlockReceipts(ref h) => {
                        executed_results.remove(h);
                    }
                    CacheId::TransactionAddress(ref h) => {
                        tx_address.remove(h);
                    }
                    CacheId::CompactBlock(ref h) => {
                        compact_blocks.remove(h);
                    }
                    CacheId::BlockHeader(ref h) => {
                        block_headers.remove(h);
                    }
                }
            }

            block_headers.size_of(malloc_ops)
                + blocks.size_of(malloc_ops)
                + executed_results.size_of(malloc_ops)
                + tx_address.size_of(malloc_ops)
                + compact_blocks.size_of(malloc_ops)
        });

        block_headers.shrink_to_fit();
        blocks.shrink_to_fit();
        executed_results.shrink_to_fit();
        tx_address.shrink_to_fit();
        compact_blocks.shrink_to_fit();
        exeuction_contexts.shrink_to_fit();
    }

    pub fn gc_cache(&self) {
        self.block_cache_gc();
        self.tx_data_manager.tx_cache_gc();
    }

    pub fn set_cur_consensus_era_genesis_hash(
        &self, cur_era_hash: &H256, next_era_hash: &H256,
    ) {
        self.insert_checkpoint_hashes_to_db(cur_era_hash, next_era_hash);

        let mut era_hash = self.cur_consensus_era_genesis_hash.write();
        let mut stable_hash = self.cur_consensus_era_stable_hash.write();
        *era_hash = cur_era_hash.clone();
        *stable_hash = next_era_hash.clone();
    }

    pub fn get_cur_consensus_era_genesis_hash(&self) -> H256 {
        self.cur_consensus_era_genesis_hash.read().clone()
    }

    pub fn get_cur_consensus_era_stable_hash(&self) -> H256 {
        self.cur_consensus_era_stable_hash.read().clone()
    }

    pub fn insert_consensus_graph_execution_info_to_db(
        &self, hash: &H256, ctx: &ConsensusGraphExecutionInfo,
    ) {
        let mut dbops = self.db.key_value().transaction();
        dbops.put(
            COL_EXECUTION_CONTEXT,
            &Self::epoch_execution_result_key(hash),
            &rlp::encode(ctx),
        );
        self.commit_db_transaction(dbops);
    }

    pub fn consensus_graph_execution_info_from_db(
        &self, hash: &H256,
    ) -> Option<ConsensusGraphExecutionInfo> {
        let rlp_bytes = self
            .db
            .key_value()
            .get(
                COL_EXECUTION_CONTEXT,
                &Self::epoch_execution_result_key(hash),
            )
            .expect("crash for db failure")?;
        let rlp = Rlp::new(&rlp_bytes);

        Some(
            rlp.as_val()
                .expect("Wrong consensus_graph_execution_info rlp format!"),
        )
    }

    pub fn recover_unsigned_tx(
        &self, transactions: &Vec<TransactionWithSignature>,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError> {
        self.tx_data_manager.recover_unsigned_tx(transactions)
    }

    pub fn recover_block(&self, block: &mut Block) -> Result<(), DecoderError> {
        self.tx_data_manager.recover_block(block)
    }

    pub fn recover_unsigned_tx_with_order(
        &self, transactions: &Vec<TransactionWithSignature>,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError> {
        self.tx_data_manager
            .recover_unsigned_tx_with_order(transactions)
    }

    pub fn build_partial(
        &self, compact_block: &mut CompactBlock,
    ) -> Vec<usize> {
        self.tx_data_manager.build_partial(compact_block)
    }
}

pub struct DataManagerConfiguration {
    record_tx_address: bool,
    persist_header: bool,
    tx_cache_count: usize,
}

impl DataManagerConfiguration {
    pub fn new(
        record_tx_address: bool, persist_header: bool, tx_cache_count: usize,
    ) -> Self {
        Self {
            record_tx_address,
            persist_header,
            tx_cache_count,
        }
    }
}
