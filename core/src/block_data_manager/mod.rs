// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    cache_config::CacheConfig,
    cache_manager::{CacheId, CacheManager, CacheSize},
    ext_db::SystemDB,
    pow::TargetDifficultyManager,
    storage::{
        state_manager::StateIndex, utils::guarded_value::*,
        StateRootWithAuxInfo, StorageManager, StorageManagerTrait,
        StorageStateTrait,
    },
};
use cfx_types::{Bloom, H256};
use malloc_size_of::{new_malloc_size_ops, MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockUpgradableReadGuard};
use primitives::{
    block::CompactBlock,
    receipt::{
        BlockReceipts, TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING,
        TRANSACTION_OUTCOME_SUCCESS,
    },
    Block, BlockHeader, EpochId, SignedTransaction, TransactionIndex,
    TransactionWithSignature, NULL_EPOCH,
};
use rlp::DecoderError;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use threadpool::ThreadPool;
pub mod block_data_types;
pub mod db_manager;
pub mod tx_data_manager;
use crate::block_data_manager::{
    db_manager::DBManager, tx_data_manager::TransactionDataManager,
};
pub use block_data_types::*;
use derivative::Derivative;
use std::{hash::Hash, path::Path, time::Duration};

use crate::parameters::consensus_internal::REWARD_EPOCH_COUNT;
use metrics::{register_meter_with_group, Meter, MeterTimer};
lazy_static! {
    static ref TX_POOL_RECOVER_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::recover_public");
}

pub const NULLU64: u64 = !0;

/// FIXME: move it to another module.
#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[derive(DeriveMallocSizeOf)]
pub struct StateAvailabilityBoundary {
    /// This is the hash of blocks in pivot chain based on current graph.
    #[derivative(Debug = "ignore")]
    pub pivot_chain: Vec<H256>,

    pub synced_state_height: u64,
    /// This is the lower boundary height of available state.
    pub lower_bound: u64,
    /// This is the upper boundary height of available state.
    pub upper_bound: u64,
    // Optimistic execution is the feature to execute ahead of the deferred
    // execution boundary. The goal is to pipeline the transaction
    // execution and the block packaging and verification.
    // optimistic_executed_height is the number of step to go ahead
    pub optimistic_executed_height: Option<u64>,
}

impl StateAvailabilityBoundary {
    pub fn new(epoch_hash: H256, epoch_height: u64) -> Self {
        Self {
            pivot_chain: vec![epoch_hash],
            synced_state_height: 0,
            lower_bound: epoch_height,
            upper_bound: epoch_height,
            optimistic_executed_height: None,
        }
    }

    pub fn check_availability(&self, height: u64, block_hash: &H256) -> bool {
        (height == 0 || height != self.synced_state_height)
            && self.lower_bound <= height
            && height <= self.upper_bound
            && {
                let r = self.pivot_chain[(height - self.lower_bound) as usize]
                    == *block_hash;
                if !r {
                    debug!(
                        "pivot_chain={:?} should be {:?} asked is {:?}",
                        self.pivot_chain,
                        self.pivot_chain[(height - self.lower_bound) as usize],
                        block_hash
                    );
                }
                r
            }
    }

    /// Try to update `upper_bound` according to a new executed block.
    pub fn adjust_upper_bound(&mut self, executed_block: &BlockHeader) {
        let next_index = (self.upper_bound - self.lower_bound + 1) as usize;
        if next_index < self.pivot_chain.len()
            && executed_block.height() == self.upper_bound + 1
            && executed_block.hash() == self.pivot_chain[next_index]
        {
            self.upper_bound += 1;
        }
        if self.lower_bound == self.synced_state_height
            && self.synced_state_height != 0
            && self.upper_bound > self.synced_state_height
        {
            self.adjust_lower_bound(self.lower_bound + 1)
        }
    }

    /// This function will record the most recent synced_state_height for
    /// special case handling.
    pub fn set_synced_state_height(&mut self, synced_state_height: u64) {
        self.synced_state_height = synced_state_height;
    }

    /// This function will set a new lower boundary height of available state.
    /// Caller should make sure the new lower boundary height should be greater
    /// than or equal to current lower boundary height.
    /// Caller should also make sure the new lower boundary height should be
    /// less than or equal to current upper boundary height.
    pub fn adjust_lower_bound(&mut self, new_lower_bound: u64) {
        // If we are going to call this function, `upper_bound` will not be 0
        // unless it is a full node and is in header phase. And we should do
        // nothing in this case.
        if self.upper_bound == 0 {
            return;
        }
        assert!(self.lower_bound <= new_lower_bound);
        assert!(
            new_lower_bound <= self.upper_bound,
            "however {} > {}, self {:?}",
            new_lower_bound,
            self.upper_bound,
            self,
        );
        if self.synced_state_height != 0
            && new_lower_bound > self.synced_state_height + REWARD_EPOCH_COUNT
        {
            self.synced_state_height = 0;
        }
        self.pivot_chain = self
            .pivot_chain
            .split_off((new_lower_bound - self.lower_bound) as usize);
        self.lower_bound = new_lower_bound;
    }
}

pub struct BlockDataManager {
    block_headers: RwLock<HashMap<H256, Arc<BlockHeader>>>,
    blocks: RwLock<HashMap<H256, Arc<Block>>>,
    compact_blocks: RwLock<HashMap<H256, CompactBlock>>,
    block_receipts: RwLock<HashMap<H256, BlockReceiptsInfo>>,
    transaction_indices: RwLock<HashMap<H256, TransactionIndex>>,
    /// Caching for receipts_root and logs_bloom for epochs after
    /// cur_era_genesis. It is not deferred, i.e., indexed by the hash of
    /// the pivot block that produces the result when executed.
    /// It is also used for checking whether an epoch has been executed.
    /// It can be updated, i.e., adding new items, in the following cases:
    /// 1) When a new epoch gets executed in normal execution;
    /// 2) After syncing snapshot, we need to update execution commitment
    ///    for pivot blocks around snapshot block based on blaming information;
    /// 3) After recovering block graph from db, update execution commitment
    ///    from db;
    /// 4) In BlockDataManager::new(), update execution commitment
    ///    of true_genesis_block.
    epoch_execution_commitments:
        RwLock<HashMap<H256, EpochExecutionCommitment>>,
    epoch_execution_contexts: RwLock<HashMap<H256, EpochExecutionContext>>,

    invalid_block_set: RwLock<HashSet<H256>>,
    cur_consensus_era_genesis_hash: RwLock<H256>,
    cur_consensus_era_stable_hash: RwLock<H256>,
    instance_id: Mutex<u64>,

    config: DataManagerConfiguration,

    tx_data_manager: TransactionDataManager,
    db_manager: DBManager,

    /// This is the original genesis block.
    pub true_genesis: Arc<Block>,
    pub storage_manager: Arc<StorageManager>,
    cache_man: Arc<Mutex<CacheManager<CacheId>>>,
    pub target_difficulty_manager: TargetDifficultyManager,

    /// This maintains the boundary height of available state and commitments
    /// (executed but not deleted or in `ExecutionTaskQueue`).
    /// The upper bound always equal to latest executed epoch height.
    /// As for the lower bound:
    ///   1. For archive node, it always equals `cur_era_stable_height`.
    ///   2. For full node, it equals the height of remotely synchronized
    ///      state at start, and equals `cur_era_stable_height` after making a
    ///      new checkpoint.
    ///
    /// The lower boundary height will be updated when:
    ///   1. New checkpoint
    ///   2. Full Node snapshot syncing
    ///   3. New Snapshot
    ///
    /// The upper boundary height will be updated when:
    ///   1. Pivot chain switch
    ///   2. Execution of new epoch
    ///
    /// The state of an epoch is valid if and only if the height of the epoch
    /// is inside the boundary.
    pub state_availability_boundary: RwLock<StateAvailabilityBoundary>,
}

impl MallocSizeOf for BlockDataManager {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let block_headers_size = self.block_headers.read().size_of(ops);
        let blocks_size = self.blocks.read().size_of(ops);
        let compact_blocks_size = self.compact_blocks.read().size_of(ops);
        let block_receipts_size = self.block_receipts.read().size_of(ops);
        let transaction_indices_size =
            self.transaction_indices.read().size_of(ops);
        let epoch_execution_commitments_size =
            self.epoch_execution_commitments.read().size_of(ops);
        let epoch_execution_contexts_size =
            self.epoch_execution_contexts.read().size_of(ops);
        let invalid_block_set_size = self.invalid_block_set.read().size_of(ops);
        let cur_consensus_era_genesis_hash_size =
            self.cur_consensus_era_genesis_hash.read().size_of(ops);
        let cur_consensus_era_stable_hash_size =
            self.cur_consensus_era_stable_hash.read().size_of(ops);
        let cache_man_size = self.cache_man.lock().size_of(ops);
        let state_availability_boundary_size =
            self.state_availability_boundary.read().size_of(ops);

        block_headers_size
            + blocks_size
            + compact_blocks_size
            + block_receipts_size
            + transaction_indices_size
            + epoch_execution_commitments_size
            + epoch_execution_contexts_size
            + invalid_block_set_size
            + cur_consensus_era_genesis_hash_size
            + cur_consensus_era_stable_hash_size
            + self.config.size_of(ops)
            + self.tx_data_manager.size_of(ops)
            + self.true_genesis.size_of(ops)
            + cache_man_size
            + self.target_difficulty_manager.size_of(ops)
            + state_availability_boundary_size
    }
}

impl BlockDataManager {
    pub fn new(
        cache_conf: CacheConfig, true_genesis: Arc<Block>, db: Arc<SystemDB>,
        storage_manager: Arc<StorageManager>,
        worker_pool: Arc<Mutex<ThreadPool>>, config: DataManagerConfiguration,
    ) -> Self
    {
        let mb = 1024 * 1024;
        let max_cache_size = cache_conf.ledger_mb() * mb;
        let pref_cache_size = max_cache_size * 3 / 4;
        let cache_man = Arc::new(Mutex::new(CacheManager::new(
            pref_cache_size,
            max_cache_size,
            3 * mb,
        )));
        let tx_data_manager = TransactionDataManager::new(
            config.tx_cache_index_maintain_timeout,
            worker_pool,
        );
        let db_manager = match config.db_type {
            DbType::Rocksdb => DBManager::new_from_rocksdb(db),
            DbType::Sqlite => {
                DBManager::new_from_sqlite(Path::new("./sqlite_db"))
            }
        };

        let data_man = Self {
            block_headers: RwLock::new(HashMap::new()),
            blocks: RwLock::new(HashMap::new()),
            compact_blocks: Default::default(),
            block_receipts: Default::default(),
            transaction_indices: Default::default(),
            epoch_execution_commitments: Default::default(),
            epoch_execution_contexts: Default::default(),
            invalid_block_set: Default::default(),
            true_genesis: true_genesis.clone(),
            storage_manager,
            cache_man,
            instance_id: Mutex::new(0),
            config,
            target_difficulty_manager: TargetDifficultyManager::new(),
            cur_consensus_era_genesis_hash: RwLock::new(true_genesis.hash()),
            cur_consensus_era_stable_hash: RwLock::new(true_genesis.hash()),
            tx_data_manager,
            db_manager,
            state_availability_boundary: RwLock::new(
                StateAvailabilityBoundary::new(true_genesis.hash(), 0),
            ),
        };

        data_man.initialize_instance_id();

        let cur_era_genesis_hash =
            match data_man.db_manager.checkpoint_hashes_from_db() {
                None => true_genesis.hash(),
                Some((checkpoint_hash, stable_hash)) => {
                    *data_man.cur_consensus_era_genesis_hash.write() =
                        checkpoint_hash;
                    *data_man.cur_consensus_era_stable_hash.write() =
                        stable_hash;
                    checkpoint_hash
                }
            };

        debug!(
            "BlockDataManager::new() cur_era_genesis_hash: {:?}",
            &cur_era_genesis_hash
        );

        if cur_era_genesis_hash == data_man.true_genesis.hash() {
            // Only insert block body for true genesis
            data_man.insert_block(
                data_man.true_genesis.clone(),
                true, /* persistent */
            );
            // Initialize ExecutionContext for true genesis
            data_man.insert_epoch_execution_context(
                cur_era_genesis_hash,
                EpochExecutionContext {
                    start_block_number: 0,
                },
                true,
            );
            // persist local_block_info for true genesis
            data_man.db_manager.insert_local_block_info_to_db(
                &data_man.true_genesis.hash(),
                &LocalBlockInfo::new(
                    BlockStatus::Valid,
                    0,
                    data_man.get_instance_id(),
                ),
            );
            data_man.insert_epoch_execution_commitment(
                data_man.true_genesis.hash(),
                data_man.true_genesis_state_root(),
                *data_man.true_genesis.block_header.deferred_receipts_root(),
                *data_man
                    .true_genesis
                    .block_header
                    .deferred_logs_bloom_hash(),
            );
        } else {
            // Recover ExecutionContext for cur_era_genesis from db
            data_man.insert_epoch_execution_context(
                cur_era_genesis_hash,
                data_man
                    .get_epoch_execution_context(&cur_era_genesis_hash)
                    .expect("ExecutionContext exists for cur_era_genesis"),
                false, /* Not persistent because it's already in db */
            );
            // for other era genesis, we need to change the instance_id
            if let Some(mut local_block_info) = data_man
                .db_manager
                .local_block_info_from_db(&cur_era_genesis_hash)
            {
                local_block_info.instance_id = data_man.get_instance_id();
                data_man.db_manager.insert_local_block_info_to_db(
                    &cur_era_genesis_hash,
                    &local_block_info,
                );
            }
            // The commitments of cur_era_genesis will be recovered in
            // `construct_pivot_state` with other epochs
        }

        data_man
    }

    pub fn get_instance_id(&self) -> u64 { *self.instance_id.lock() }

    pub fn initialize_instance_id(&self) {
        let mut my_instance_id = self.instance_id.lock();
        if *my_instance_id == 0 {
            // load last instance id
            let instance_id = self.db_manager.instance_id_from_db();

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
                self.db_manager.local_block_info_from_db(
                    &self.get_cur_consensus_era_genesis_hash(),
                )
            {
                local_block_info.instance_id = *my_instance_id;
                self.db_manager.insert_local_block_info_to_db(
                    &self.get_cur_consensus_era_genesis_hash(),
                    &local_block_info,
                );
            }
        }

        // persist new instance id
        self.db_manager.insert_instance_id_to_db(*my_instance_id);
    }

    /// This will return the state root of true genesis block.
    pub fn true_genesis_state_root(&self) -> StateRootWithAuxInfo {
        let true_genesis_hash = self.true_genesis.hash();
        self.storage_manager
            .get_state_no_commit(
                StateIndex::new_for_readonly(
                    &true_genesis_hash,
                    &StateRootWithAuxInfo::genesis(&true_genesis_hash),
                ),
                /* try_open = */ false,
            )
            .unwrap()
            .unwrap()
            .get_state_root()
            .unwrap()
    }

    pub fn transaction_by_hash(
        &self, hash: &H256,
    ) -> Option<Arc<SignedTransaction>> {
        let tx_index = self
            .transaction_index_by_hash(hash, false /* update_cache */)?;
        let block = self.block_by_hash(
            &tx_index.block_hash,
            false, /* update_cache */
        )?;
        assert!(tx_index.index < block.transactions.len());
        Some(block.transactions[tx_index.index].clone())
    }

    /// insert block body in memory cache and db
    pub fn insert_block_body(
        &self, hash: H256, block: Arc<Block>, persistent: bool,
    ) {
        if persistent {
            self.db_manager.insert_block_body_to_db(block.as_ref());
        }
        self.cache_man.lock().note_used(CacheId::Block(hash));
        self.blocks.write().insert(hash, block);
    }

    /// remove block body in memory cache and db
    pub fn remove_block_body(&self, hash: &H256, remove_db: bool) {
        if remove_db {
            self.db_manager.remove_block_body_from_db(hash);
        }
        self.blocks.write().remove(hash);
    }

    /// TODO Also set block header
    pub fn block_by_hash(
        &self, hash: &H256, update_cache: bool,
    ) -> Option<Arc<Block>> {
        self.get(
            hash,
            &self.blocks,
            |key| self.db_manager.block_from_db(key).map(Arc::new),
            if update_cache {
                Some(CacheId::Block(*hash))
            } else {
                None
            },
        )
    }

    /// This function returns the block from db without wrapping it in `Arc`.
    pub fn block_from_db(&self, hash: &H256) -> Option<Block> {
        self.db_manager.block_from_db(hash)
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

    /// remove block body and block header in memory cache and db
    pub fn remove_block(&self, hash: &H256, remove_db: bool) {
        self.remove_block_header(hash, remove_db);
        self.remove_block_body(hash, remove_db);
    }

    pub fn block_header_by_hash(
        &self, hash: &H256,
    ) -> Option<Arc<BlockHeader>> {
        self.get(
            hash,
            &self.block_headers,
            |key| self.db_manager.block_header_from_db(key).map(Arc::new),
            Some(CacheId::BlockHeader(*hash)),
        )
    }

    pub fn insert_block_header(
        &self, hash: H256, header: Arc<BlockHeader>, persistent: bool,
    ) {
        self.insert(
            hash,
            header,
            &self.block_headers,
            |_, value| {
                self.db_manager.insert_block_header_to_db(value.as_ref())
            },
            Some(CacheId::BlockHeader(hash)),
            persistent,
        )
    }

    /// remove block header in memory cache and db
    pub fn remove_block_header(&self, hash: &H256, remove_db: bool) {
        if remove_db {
            self.db_manager.remove_block_header_from_db(hash);
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

    /// Return None if receipts for corresponding epoch is not computed before
    /// or has been overwritten by another new pivot chain in db
    ///
    /// This function will require lock of block_receipts
    pub fn block_execution_result_by_hash_with_epoch(
        &self, hash: &H256, assumed_epoch: &H256, update_cache: bool,
    ) -> Option<BlockExecutionResult> {
        let maybe_receipts =
            self.block_receipts
                .read()
                .get(hash)
                .and_then(|receipt_info| {
                    receipt_info.get_receipts_at_epoch(assumed_epoch)
                });
        if maybe_receipts.is_some() {
            if update_cache {
                self.cache_man
                    .lock()
                    .note_used(CacheId::BlockReceipts(*hash));
            }
            return maybe_receipts;
        }
        let BlockExecutionResultWithEpoch(epoch, receipts) =
            self.db_manager.block_execution_result_from_db(hash)?;
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

    pub fn block_execution_result_by_hash_from_db(
        &self, hash: &H256,
    ) -> Option<BlockExecutionResultWithEpoch> {
        self.db_manager.block_execution_result_from_db(hash)
    }

    pub fn block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.block_execution_result_by_hash_from_db(&hash)
            .map(|execution_result| execution_result.0)
            .and_then(|pivot| self.block_header_by_hash(&pivot))
            .map(|header| header.height())
    }

    pub fn insert_block_results(
        &self, hash: H256, epoch: H256, block_receipts: Arc<BlockReceipts>,
        persistent: bool,
    )
    {
        let bloom =
            block_receipts
                .receipts
                .iter()
                .fold(Bloom::zero(), |mut b, r| {
                    b.accrue_bloom(&r.log_bloom);
                    b
                });
        let result = BlockExecutionResultWithEpoch(
            epoch,
            BlockExecutionResult {
                block_receipts,
                bloom,
            },
        );

        if persistent {
            self.db_manager
                .insert_block_execution_result_to_db(&hash, &result);
        }

        let mut block_receipts = self.block_receipts.write();
        let receipt_info = block_receipts
            .entry(hash)
            .or_insert(BlockReceiptsInfo::default());
        receipt_info.insert_receipts_at_epoch(&epoch, result.1);

        self.cache_man
            .lock()
            .note_used(CacheId::BlockReceipts(hash));
    }

    pub fn remove_block_results(&self, hash: &H256, remove_db: bool) {
        self.block_receipts.write().remove(hash);
        if remove_db {
            self.db_manager.remove_block_execution_result_from_db(hash);
        }
    }

    pub fn transaction_index_by_hash(
        &self, hash: &H256, update_cache: bool,
    ) -> Option<TransactionIndex> {
        self.get(
            hash,
            &self.transaction_indices,
            |key| self.db_manager.transaction_index_from_db(key),
            if update_cache {
                Some(CacheId::TransactionAddress(*hash))
            } else {
                None
            },
        )
    }

    pub fn insert_transaction_index(
        &self, hash: &H256, tx_index: &TransactionIndex,
    ) {
        if !self.config.record_tx_index {
            return;
        }
        // transaction_indices will not be updated if it's not inserted before
        self.transaction_indices
            .write()
            .entry(*hash)
            .and_modify(|v| {
                *v = tx_index.clone();
                self.cache_man
                    .lock()
                    .note_used(CacheId::TransactionAddress(*hash));
            });
        self.db_manager
            .insert_transaction_index_to_db(hash, tx_index);
    }

    fn insert<K, V, InsertF>(
        &self, key: K, value: V, in_mem: &RwLock<HashMap<K, V>>,
        insert_f: InsertF, maybe_cache_id: Option<CacheId>, persistent: bool,
    ) where
        K: Clone + Eq + Hash,
        InsertF: Fn(&K, &V),
    {
        if persistent {
            insert_f(&key, &value);
        }
        in_mem.write().insert(key.clone(), value);
        if let Some(cache_id) = maybe_cache_id {
            self.cache_man.lock().note_used(cache_id);
        }
    }

    fn get<K, V, LoadF>(
        &self, key: &K, in_mem: &RwLock<HashMap<K, V>>, load_f: LoadF,
        maybe_cache_id: Option<CacheId>,
    ) -> Option<V>
    where
        K: Clone + Eq + Hash,
        V: Clone,
        LoadF: Fn(&K) -> Option<V>,
    {
        let upgradable_read_lock = in_mem.upgradable_read();
        if let Some(value) = upgradable_read_lock.get(key) {
            return Some(value.clone());
        }
        load_f(key).map(|value| {
            if let Some(cache_id) = maybe_cache_id {
                RwLockUpgradableReadGuard::upgrade(upgradable_read_lock)
                    .insert(key.clone(), value.clone());
                self.cache_man.lock().note_used(cache_id);
            }
            value
        })
    }

    pub fn insert_local_block_info_to_db(
        &self, hash: &H256, info: LocalBlockInfo,
    ) {
        self.db_manager.insert_local_block_info_to_db(hash, &info)
    }

    pub fn local_block_info_from_db(
        &self, hash: &H256,
    ) -> Option<LocalBlockInfo> {
        self.db_manager.local_block_info_from_db(hash)
    }

    pub fn insert_terminals_to_db(&self, terminals: Vec<H256>) {
        self.db_manager.insert_terminals_to_db(&terminals)
    }

    pub fn terminals_from_db(&self) -> Option<Vec<H256>> {
        self.db_manager.terminals_from_db()
    }

    pub fn insert_executed_epoch_set_hashes_to_db(
        &self, epoch_number: u64, epoch_set: &Vec<H256>,
    ) {
        self.db_manager
            .insert_executed_epoch_set_hashes_to_db(epoch_number, epoch_set);
    }

    pub fn insert_skipped_epoch_set_hashes_to_db(
        &self, epoch_number: u64, skipped_set: &Vec<H256>,
    ) {
        self.db_manager
            .insert_skipped_epoch_set_hashes_to_db(epoch_number, skipped_set);
    }

    pub fn executed_epoch_set_hashes_from_db(
        &self, epoch_number: u64,
    ) -> Option<Vec<H256>> {
        if epoch_number != 0 {
            self.db_manager
                .executed_epoch_set_hashes_from_db(epoch_number)
        } else {
            Some(vec![self.true_genesis.hash()])
        }
    }

    pub fn skipped_epoch_set_hashes_from_db(
        &self, epoch_number: u64,
    ) -> Option<Vec<H256>> {
        if epoch_number != 0 {
            self.db_manager
                .skipped_epoch_set_hashes_from_db(epoch_number)
        } else {
            Some(vec![])
        }
    }

    pub fn all_epoch_set_hashes_from_db(
        &self, epoch_number: u64,
    ) -> Option<Vec<H256>> {
        if epoch_number != 0 {
            let mut res = self
                .db_manager
                .skipped_epoch_set_hashes_from_db(epoch_number)?;
            res.append(
                &mut self
                    .db_manager
                    .executed_epoch_set_hashes_from_db(epoch_number)?,
            );
            Some(res)
        } else {
            Some(vec![self.true_genesis.hash()])
        }
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

    pub fn insert_epoch_execution_context(
        &self, hash: H256, ctx: EpochExecutionContext, persistent: bool,
    ) {
        self.insert(
            hash,
            ctx,
            &self.epoch_execution_contexts,
            |key, value| {
                self.db_manager.insert_execution_context_to_db(key, value)
            },
            None,
            persistent,
        );
    }

    /// The in-memory state will not be updated because it's only garbage
    /// collected explicitly when we make checkpoints.
    pub fn get_epoch_execution_context(
        &self, hash: &H256,
    ) -> Option<EpochExecutionContext> {
        self.get(
            hash,
            &self.epoch_execution_contexts,
            |key| self.db_manager.execution_context_from_db(key),
            None,
        )
    }

    /// TODO We can avoid persisting execution_commitments for blocks
    /// not on the pivot chain after a checkpoint
    pub fn insert_epoch_execution_commitment(
        &self, block_hash: H256,
        state_root_with_aux_info: StateRootWithAuxInfo, receipts_root: H256,
        logs_bloom_hash: H256,
    )
    {
        let commitment = EpochExecutionCommitment {
            state_root_with_aux_info,
            receipts_root,
            logs_bloom_hash,
        };
        self.insert(
            block_hash,
            commitment,
            &self.epoch_execution_commitments,
            |key, value| {
                self.db_manager
                    .insert_epoch_execution_commitment_to_db(key, value)
            },
            None,
            true,
        );
    }

    /// Get in-mem execution commitment.
    pub fn get_epoch_execution_commitment(
        &self, block_hash: &H256,
    ) -> GuardedValue<
        RwLockReadGuard<'_, HashMap<H256, EpochExecutionCommitment>>,
        NonCopy<Option<&'_ EpochExecutionCommitment>>,
    > {
        let read_lock = self.epoch_execution_commitments.read();
        let (read_lock, derefed) = GuardedValue::new_derefed(read_lock).into();
        GuardedValue::new(read_lock, NonCopy(derefed.0.get(block_hash)))
    }

    /// Load commitment from db.
    /// The caller should ensure that the loaded commitment is after
    /// cur_era_genesis and can be garbage-collected by checkpoint.
    pub fn load_epoch_execution_commitment_from_db(
        &self, block_hash: &H256,
    ) -> Option<EpochExecutionCommitment> {
        let commitment = self
            .db_manager
            .epoch_execution_commitment_from_db(block_hash)?;
        self.epoch_execution_commitments
            .write()
            .insert(*block_hash, commitment.clone());
        Some(commitment)
    }

    /// Get persisted execution commitment.
    /// It will check db if it's missing in db.
    pub fn get_epoch_execution_commitment_with_db(
        &self, block_hash: &H256,
    ) -> Option<EpochExecutionCommitment> {
        self.get_epoch_execution_commitment(block_hash).map_or_else(
            || {
                self.db_manager
                    .epoch_execution_commitment_from_db(block_hash)
            },
            |maybe_ref| Some(maybe_ref.clone()),
        )
    }

    pub fn remove_epoch_execution_commitment(&self, block_hash: &H256) {
        self.epoch_execution_commitments.write().remove(block_hash);
    }

    pub fn remove_epoch_execution_commitment_from_db(&self, block_hash: &H256) {
        self.db_manager
            .remove_epoch_execution_commitment_from_db(block_hash);
    }

    pub fn remove_epoch_execution_context(&self, block_hash: &H256) {
        self.epoch_execution_contexts.write().remove(block_hash);
    }

    pub fn remove_epoch_execution_context_from_db(&self, block_hash: &H256) {
        self.db_manager
            .remove_block_execution_result_from_db(block_hash);
    }

    pub fn epoch_executed(&self, epoch_hash: &H256) -> bool {
        // `block_receipts_root` is not computed when recovering from db
        self.get_epoch_execution_commitment(epoch_hash).is_some()
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

        if self.config.record_tx_index && on_local_pivot {
            // Check if all blocks receipts are from this epoch
            let mut epoch_receipts = Vec::new();
            for h in epoch_block_hashes {
                if let Some(r) = self.block_execution_result_by_hash_with_epoch(
                    h, epoch_hash, true, /* update_cache */
                ) {
                    epoch_receipts.push(r.block_receipts);
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
                        .receipts
                        .get(tx_idx)
                        .unwrap()
                        .outcome_status
                    {
                        TRANSACTION_OUTCOME_SUCCESS
                        | TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING => {
                            self.insert_transaction_index(
                                &tx.hash,
                                &TransactionIndex {
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
        self.db_manager
            .insert_local_block_info_to_db(&block_hash, &block_info);
        self.invalid_block_set.write().insert(block_hash);
    }

    /// Check if a block is already marked as invalid.
    pub fn verified_invalid(
        &self, block_hash: &H256,
    ) -> (bool, Option<LocalBlockInfo>) {
        let invalid_block_set = self.invalid_block_set.upgradable_read();
        if invalid_block_set.contains(block_hash) {
            return (true, None);
        } else {
            if let Some(block_info) =
                self.db_manager.local_block_info_from_db(block_hash)
            {
                match block_info.get_status() {
                    BlockStatus::Invalid => {
                        RwLockUpgradableReadGuard::upgrade(invalid_block_set)
                            .insert(*block_hash);
                        return (true, Some(block_info));
                    }
                    _ => return (false, Some(block_info)),
                }
            } else {
                // No status on disk, so the block is not marked invalid before
                return (false, None);
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
        let transaction_indices =
            self.transaction_indices.read().size_of(malloc_ops);
        CacheSize {
            block_headers,
            blocks,
            block_receipts,
            transaction_indices,
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
        let mut tx_indices = self.transaction_indices.write();
        let mut exeuction_contexts = self.epoch_execution_contexts.write();
        let mut cache_man = self.cache_man.lock();
        debug!(
            "Before gc cache_size={} {} {} {} {}",
            current_size,
            blocks.len(),
            compact_blocks.len(),
            executed_results.len(),
            tx_indices.len(),
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
                        tx_indices.remove(h);
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
                + tx_indices.size_of(malloc_ops)
                + compact_blocks.size_of(malloc_ops)
        });

        block_headers.shrink_to_fit();
        blocks.shrink_to_fit();
        executed_results.shrink_to_fit();
        tx_indices.shrink_to_fit();
        compact_blocks.shrink_to_fit();
        exeuction_contexts.shrink_to_fit();
    }

    pub fn cache_gc(&self) { self.block_cache_gc(); }

    pub fn set_cur_consensus_era_genesis_hash(
        &self, cur_era_hash: &H256, next_era_hash: &H256,
    ) {
        self.db_manager
            .insert_checkpoint_hashes_to_db(cur_era_hash, next_era_hash);

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

    pub fn recover_unsigned_tx(
        &self, transactions: &Vec<TransactionWithSignature>,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError> {
        let _timer = MeterTimer::time_func(TX_POOL_RECOVER_TIMER.as_ref());
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

    pub fn find_missing_tx_indices_encoded(
        &self, compact_block: &mut CompactBlock,
    ) -> Vec<usize> {
        self.tx_data_manager
            .find_missing_tx_indices_encoded(compact_block)
    }

    /// Caller should make sure the state exists.
    pub fn get_state_readonly_index<'a>(
        &'a self, block_hash: &'a EpochId,
    ) -> GuardedValue<
        RwLockReadGuard<'a, HashMap<H256, EpochExecutionCommitment>>,
        Option<StateIndex<'a>>,
    > {
        let (guard, maybe_commitment) =
            self.get_epoch_execution_commitment(block_hash).into();
        let maybe_state_index = match &*maybe_commitment {
            None => None,
            Some(execution_commitment) => Some(StateIndex::new_for_readonly(
                block_hash,
                &execution_commitment.state_root_with_aux_info,
            )),
        };

        GuardedValue::new(guard, maybe_state_index)
    }

    // TODO: There could be io error when getting block by hash.
    pub fn get_parent_epochs_for(
        &self, mut block: EpochId, mut count: u64,
    ) -> (EpochId, Vec<EpochId>) {
        let mut epochs_reverse_order = vec![];
        while count > 0 {
            debug!("getting parent for block {:?}", block);
            epochs_reverse_order.push(block);
            block = *self.block_header_by_hash(&block).unwrap().parent_hash();
            if block == NULL_EPOCH
                || block == *self.cur_consensus_era_genesis_hash.read()
            {
                break;
            }
            count -= 1;
        }

        debug!("get_parent_epochs stopped at block {:?}", block);
        epochs_reverse_order.reverse();
        (block, epochs_reverse_order)
    }

    pub fn get_snapshot_epoch_count(&self) -> u32 {
        self.storage_manager
            .get_storage_manager()
            .get_snapshot_epoch_count()
    }

    pub fn get_snapshot_blame_plus_depth(&self) -> usize {
        // We need the extra + 1 to get a state root that points to the
        // snapshot we want.
        self.storage_manager
            .get_storage_manager()
            .get_snapshot_epoch_count() as usize
            + 1
    }
}

#[derive(Copy, Clone)]
pub enum DbType {
    Rocksdb,
    Sqlite,
}

pub struct DataManagerConfiguration {
    record_tx_index: bool,
    tx_cache_index_maintain_timeout: Duration,
    db_type: DbType,
}

impl MallocSizeOf for DataManagerConfiguration {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl DataManagerConfiguration {
    pub fn new(
        record_tx_index: bool, tx_cache_index_maintain_timeout: Duration,
        db_type: DbType,
    ) -> Self
    {
        Self {
            record_tx_index,
            tx_cache_index_maintain_timeout,
            db_type,
        }
    }
}
