// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    cache_manager::{CacheId, CacheManager},
    db::{COL_BLOCKS, COL_BLOCK_RECEIPTS, COL_TX_ADDRESS},
    ext_db::SystemDB,
    storage::StorageManager,
    verification::VerificationConfig,
    SharedTransactionPool,
};
use cfx_types::{Bloom, H256};
use heapsize::HeapSizeOf;
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use primitives::{
    receipt::{Receipt, TRANSACTION_OUTCOME_SUCCESS},
    Block, BlockHeader, SignedTransaction, TransactionAddress,
};
use rlp::{Rlp, RlpStream};
use std::{collections::HashMap, sync::Arc};

const BLOCK_STATUS_SUFFIX_BYTE: u8 = 1;

pub struct BlockDataManager {
    pub block_headers: RwLock<HashMap<H256, Arc<BlockHeader>>>,
    pub blocks: RwLock<HashMap<H256, Arc<Block>>>,
    pub block_receipts: RwLock<HashMap<H256, BlockReceiptsInfo>>,
    pub transaction_addresses: RwLock<HashMap<H256, TransactionAddress>>,
    block_receipts_root: RwLock<HashMap<H256, H256>>,

    pub record_tx_address: bool,

    pub txpool: SharedTransactionPool,
    pub genesis_block: Arc<Block>,
    pub db: Arc<SystemDB>,
    pub storage_manager: Arc<StorageManager>,
    pub cache_man: Arc<Mutex<CacheManager<CacheId>>>,
}

impl BlockDataManager {
    pub fn new(
        genesis_block: Arc<Block>, txpool: SharedTransactionPool,
        db: Arc<SystemDB>, storage_manager: Arc<StorageManager>,
        cache_man: Arc<Mutex<CacheManager<CacheId>>>, record_tx_address: bool,
    ) -> Self
    {
        let data_man = Self {
            block_headers: RwLock::new(HashMap::new()),
            blocks: RwLock::new(HashMap::new()),
            block_receipts: Default::default(),
            transaction_addresses: Default::default(),
            block_receipts_root: Default::default(),
            txpool,
            genesis_block,
            db,
            storage_manager,
            cache_man,
            record_tx_address,
        };

        data_man.insert_receipts_root(
            data_man.genesis_block.hash(),
            *data_man.genesis_block.block_header.deferred_receipts_root(),
        );
        data_man.insert_block_header(
            data_man.genesis_block.hash(),
            Arc::new(data_man.genesis_block.block_header.clone()),
        );
        data_man.insert_block_to_kv(data_man.genesis_block(), true);
        data_man
    }

    pub fn genesis_block(&self) -> Arc<Block> { self.genesis_block.clone() }

    pub fn transaction_by_hash(
        &self, hash: &H256,
    ) -> Option<Arc<SignedTransaction>> {
        let address = self.transaction_address_by_hash(hash, false)?;
        let block = self.block_by_hash(&address.block_hash, false)?;
        assert!(address.index < block.transactions.len());
        Some(block.transactions[address.index].clone())
    }

    pub fn block_by_hash_from_db(&self, hash: &H256) -> Option<Block> {
        debug!("Loading block {} from db", hash);
        let block = self.db.key_value().get(COL_BLOCKS, hash)
            .expect("Low level database error when fetching block. Some issue with disk?")?;
        let rlp = Rlp::new(&block);
        let mut block = Block::decode_with_tx_public(&rlp)
            .expect("Wrong block rlp format!");
        debug!("Finish constructing block {} from db", hash);
        //let mut block = rlp.as_val::<Block>().expect("Wrong block rlp
        // format!"); SynchronizationProtocolHandler::recover_public(
        //    &mut block,
        //    &mut *self.txpool.transaction_pubkey_cache.write(),
        //    &mut *self.cache_man.lock(),
        //    &*self.worker_pool.lock(),
        //)
        //.expect("Failed to recover public!");
        VerificationConfig::compute_header_pow_quality(&mut block.block_header);
        Some(block)
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

        let block = self.block_by_hash_from_db(hash)?;
        let block = Arc::new(block);

        if update_cache {
            let mut write = self.blocks.write();
            write.insert(*hash, block.clone());
            self.cache_man.lock().note_used(CacheId::Block(*hash));
        }
        Some(block)
    }

    pub fn blocks_by_hash_list(
        &self, hashes: &Vec<H256>, update_cache: bool,
    ) -> Option<Vec<Arc<Block>>> {
        let mut epoch_blocks = Vec::new();
        for h in hashes {
            epoch_blocks.push(self.block_by_hash(h, update_cache)?);
        }
        Some(epoch_blocks)
    }

    pub fn insert_block_to_kv(&self, block: Arc<Block>, persistent: bool) {
        let hash = block.hash();

        if persistent {
            let mut dbops = self.db.key_value().transaction();
            //dbops.put(COL_BLOCKS, &hash, &rlp::encode(block.as_ref()));
            dbops.put(COL_BLOCKS, &hash, &block.encode_with_tx_public());
            self.db
                .key_value()
                .write(dbops)
                .expect("crash for db failure");
        }

        self.blocks.write().insert(hash, block);
        self.cache_man.lock().note_used(CacheId::Block(hash));
    }

    /// Store block status to db. Now the status means if the block is partial
    /// invalid.
    /// The db key is the block hash plus one extra byte, so we can get better
    /// data locality if we get both a block and its status from db.
    /// The status is not a part of the block because the block is inserted
    /// before we know its status, and we do not want to insert a large chunk
    /// again. TODO Maybe we can use in-place modification (operator `merge`
    /// in rocksdb) to keep the status together with the block.
    pub fn insert_block_status_to_db(
        &self, block_hash: &H256, partial_invalid: bool,
    ) {
        let mut dbops = self.db.key_value().transaction();
        let mut key = Vec::with_capacity(block_hash.len() + 1);
        key.extend_from_slice(&block_hash);
        key.push(BLOCK_STATUS_SUFFIX_BYTE);
        let value = if partial_invalid { [1] } else { [0] };
        dbops.put(COL_BLOCKS, &key, &value);
        self.db
            .key_value()
            .write(dbops)
            .expect("crash for db failure");
    }

    /// Get block status from db. Now the status means if the block is partial
    /// invalid
    pub fn block_status_from_db(&self, block_hash: &H256) -> Option<bool> {
        let mut key = Vec::with_capacity(block_hash.len() + 1);
        key.extend_from_slice(&block_hash);
        key.push(BLOCK_STATUS_SUFFIX_BYTE);
        self.db
            .key_value()
            .get(COL_BLOCKS, &key)
            .expect("crash for db failure")
            .map(|encoded| {
                // TODO May encode more data in the future, and should use an
                // better structure for encoding and decoding
                encoded[0] == 1
            })
    }

    pub fn remove_block_from_kv(&self, hash: &H256) {
        self.blocks.write().remove(hash);
        let mut dbops = self.db.key_value().transaction();
        dbops.delete(COL_BLOCKS, hash);
        self.db
            .key_value()
            .write(dbops)
            .expect("crash for db failure");
    }

    pub fn block_header_by_hash(
        &self, hash: &H256,
    ) -> Option<Arc<BlockHeader>> {
        // TODO If we persist headers, we should try to get it from db
        self.block_headers
            .read()
            .get(hash)
            .map(|header_ref| header_ref.clone())
    }

    pub fn insert_block_header(
        &self, hash: H256, header: Arc<BlockHeader>,
    ) -> Option<Arc<BlockHeader>> {
        self.block_headers.write().insert(hash, header)
    }

    pub fn remove_block_header(&self, hash: &H256) -> Option<Arc<BlockHeader>> {
        self.block_headers.write().remove(hash)
    }

    pub fn block_height_by_hash(&self, hash: &H256) -> Option<u64> {
        let result = self.block_by_hash(hash, false)?;
        Some(result.block_header.height())
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

    pub fn insert_block_results_to_kv(
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
            self.db
                .key_value()
                .write(dbops)
                .expect("crash for db failure");
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

    pub fn insert_transaction_address_to_kv(
        &self, hash: &H256, tx_address: &TransactionAddress,
    ) {
        if !self.record_tx_address {
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
        self.db
            .key_value()
            .write(dbops)
            .expect("crash for db failure");
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

    pub fn insert_receipts_root(
        &self, block_hash: H256, receipts_root: H256,
    ) -> Option<H256> {
        self.block_receipts_root
            .write()
            .insert(block_hash, receipts_root)
    }

    pub fn get_receipts_root(&self, block_hash: &H256) -> Option<H256> {
        self.block_receipts_root
            .read()
            .get(block_hash)
            .map(Clone::clone)
    }

    /// Check if all executed results of an epoch exist
    pub fn epoch_executed_and_recovered(
        &self, epoch_hash: &H256, epoch_block_hashes: &Vec<H256>,
        on_local_pivot: bool,
    ) -> bool
    {
        // `block_receipts_root` is not computed when recovering from db with
        // fast_recover == false And we should force it to recompute
        // without checking receipts when fast_recover == false
        if self.get_receipts_root(epoch_hash).is_none() {
            return false;
        }
        let mut epoch_receipts = Vec::new();
        for h in epoch_block_hashes {
            if let Some(r) =
                self.block_results_by_hash_with_epoch(h, epoch_hash, true)
            {
                epoch_receipts.push(r.receipts);
            } else {
                return false;
            }
        }

        // Recover tx address if we will skip pivot chain execution
        if on_local_pivot && self.record_tx_address {
            for (block_idx, block_hash) in epoch_block_hashes.iter().enumerate()
            {
                let block =
                    self.block_by_hash(block_hash, true).expect("block exists");
                for (tx_idx, tx) in block.transactions.iter().enumerate() {
                    if epoch_receipts[block_idx]
                        .get(tx_idx)
                        .unwrap()
                        .outcome_status
                        == TRANSACTION_OUTCOME_SUCCESS
                    {
                        self.insert_transaction_address_to_kv(
                            &tx.hash,
                            &TransactionAddress {
                                block_hash: *block_hash,
                                index: tx_idx,
                            },
                        )
                    }
                }
            }
        }
        true
    }
}

#[derive(Clone, Debug)]
pub struct BlockExecutedResult {
    pub receipts: Arc<Vec<Receipt>>,
    pub bloom: Bloom,
}
impl HeapSizeOf for BlockExecutedResult {
    fn heap_size_of_children(&self) -> usize {
        self.receipts.heap_size_of_children()
    }
}
type EpochIndex = H256;

#[derive(Default, Debug)]
pub struct BlockReceiptsInfo {
    info_with_epoch: Vec<(EpochIndex, BlockExecutedResult)>,
}

impl HeapSizeOf for BlockReceiptsInfo {
    fn heap_size_of_children(&self) -> usize {
        self.info_with_epoch.heap_size_of_children()
    }
}

impl BlockReceiptsInfo {
    /// `epoch` is the index of the epoch id in consensus arena
    pub fn get_receipts_at_epoch(
        &self, epoch: &EpochIndex,
    ) -> Option<BlockExecutedResult> {
        for (e_id, receipts) in &self.info_with_epoch {
            if *e_id == *epoch {
                return Some(receipts.clone());
            }
        }
        None
    }

    /// Insert the tx fee when the block is included in epoch `epoch`
    pub fn insert_receipts_at_epoch(
        &mut self, epoch: &EpochIndex, receipts: BlockExecutedResult,
    ) {
        // If it's inserted before, the fee must be the same, so we do not add
        // duplicate entry
        if self.get_receipts_at_epoch(epoch).is_none() {
            self.info_with_epoch.push((*epoch, receipts));
        }
    }

    /// Only keep the tx fee in the given `epoch`
    /// Called after we process rewards, and other fees will not be used w.h.p.
    pub fn retain_epoch(&mut self, epoch: &EpochIndex) {
        self.info_with_epoch.retain(|(e_id, _)| *e_id == *epoch);
    }
}
