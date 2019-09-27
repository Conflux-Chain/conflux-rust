use crate::{cache_manager::CacheManager, WORKER_COMPUTATION_PARALLELISM};
use cfx_types::H256;
use metrics::{register_queue, Queue};
use parking_lot::{Mutex, RwLock};
use primitives::{
    block::{from_tx_hash, get_shortid_key, CompactBlock},
    Block, SignedTransaction, TransactionWithSignature,
};
use rlp::DecoderError;
use std::{
    collections::HashMap,
    sync::{mpsc::channel, Arc},
};
use threadpool::ThreadPool;

lazy_static! {
    static ref RECOVER_PUB_KEY_QUEUE: Arc<dyn Queue> =
        register_queue("recover_public_key_queue");
}

pub struct TransactionDataManager {
    tx_cache: RwLock<HashMap<H256, Arc<SignedTransaction>>>,
    worker_pool: Arc<Mutex<ThreadPool>>,
    tx_cache_man: Mutex<CacheManager<H256>>,
}

impl TransactionDataManager {
    pub fn new(
        tx_cache_count: usize, worker_pool: Arc<Mutex<ThreadPool>>,
    ) -> Self {
        // TODO Bound both the size and the count of tx
        let tx_cache_man = Mutex::new(CacheManager::new(
            tx_cache_count * 3 / 4,
            tx_cache_count,
            10000,
        ));
        Self {
            tx_cache: Default::default(),
            worker_pool,
            tx_cache_man,
        }
    }

    /// Recover the public keys for uncached transactions in `transactions`.
    /// If a tx is already in the cache, it will be ignored and not included in
    /// the output vec.
    pub fn recover_unsigned_tx(
        &self, transactions: &Vec<TransactionWithSignature>,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError> {
        let uncached_trans = {
            let tx_cache = self.tx_cache.read();
            transactions
                .iter()
                .filter(|tx| {
                    let tx_hash = tx.hash();
                    let inserted = tx_cache.contains_key(&tx_hash);
                    // Sample 1/128 transactions
                    if tx_hash[0] & 254 == 0 {
                        debug!("Sampled transaction {:?} in tx pool", tx_hash);
                    }
                    !inserted
                })
                .map(|tx| (0, tx.clone())) // idx not used
                .collect()
        };
        // Ignore the index and return the recovered tx list
        self.recover_uncached_tx(uncached_trans)
            .map(|tx_vec| tx_vec.into_iter().map(|(_, tx)| tx).collect())
    }

    /// Recover public keys for the transactions in `block`.
    ///
    /// The public keys already in input transactions will be used directly
    /// without verification. `block` will not be updated if any error is
    /// thrown.
    pub fn recover_block(&self, block: &mut Block) -> Result<(), DecoderError> {
        let (uncached_trans, mut recovered_trans) = {
            let tx_cache = self.tx_cache.read();
            let mut uncached_trans = Vec::new();
            let mut recovered_trans = Vec::new();
            for (idx, transaction) in block.transactions.iter().enumerate() {
                if transaction.public.is_some() {
                    // This may only happen for `GetBlocksWithPublicResponse`
                    // for now.
                    recovered_trans.push(Some(transaction.clone()));
                    continue;
                }
                let tx_hash = transaction.hash();
                // Sample 1/128 transactions
                if tx_hash[0] & 254 == 0 {
                    debug!("Sampled transaction {:?} in block", tx_hash);
                }
                match tx_cache.get(&tx_hash) {
                    Some(tx) => recovered_trans.push(Some(tx.clone())),
                    None => {
                        uncached_trans
                            .push((idx, transaction.transaction.clone()));
                        recovered_trans.push(None);
                    }
                }
            }
            (uncached_trans, recovered_trans)
        };
        for (idx, tx) in self.recover_uncached_tx(uncached_trans)? {
            recovered_trans[idx] = Some(tx);
        }
        block.transactions = recovered_trans
            .into_iter()
            .map(|e| e.expect("All tx recovered"))
            .collect();
        Ok(())
    }

    pub fn recover_unsigned_tx_with_order(
        &self, transactions: &Vec<TransactionWithSignature>,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError> {
        let (uncached_trans, mut recovered_trans) = {
            let tx_cache = self.tx_cache.read();
            let mut uncached_trans = Vec::new();
            let mut recovered_trans = Vec::new();
            for (idx, transaction) in transactions.iter().enumerate() {
                let tx_hash = transaction.hash();
                // Sample 1/128 transactions
                if tx_hash[0] & 254 == 0 {
                    debug!("Sampled transaction {:?} in block", tx_hash);
                }
                match tx_cache.get(&tx_hash) {
                    Some(tx) => recovered_trans.push(Some(tx.clone())),
                    None => {
                        uncached_trans.push((idx, transaction.clone()));
                        recovered_trans.push(None);
                    }
                }
            }
            (uncached_trans, recovered_trans)
        };
        for (idx, tx) in self.recover_uncached_tx(uncached_trans)? {
            recovered_trans[idx] = Some(tx);
        }
        Ok(recovered_trans
            .into_iter()
            .map(|e| e.expect("All tx recovered"))
            .collect())
    }

    /// Recover public key for `uncached_trans` and keep the corresponding index
    /// unchanged.
    ///
    /// Note that we release `tx_cache` lock during pubkey recovery to allow
    /// more parallelism, but we may recover a tx twice if it is received
    /// again before the recovery finishes.
    fn recover_uncached_tx(
        &self, uncached_trans: Vec<(usize, TransactionWithSignature)>,
    ) -> Result<Vec<(usize, Arc<SignedTransaction>)>, DecoderError> {
        let mut recovered_trans = Vec::new();
        if uncached_trans.len() < WORKER_COMPUTATION_PARALLELISM * 8 {
            for (idx, tx) in uncached_trans {
                if let Ok(public) = tx.recover_public() {
                    recovered_trans.push((
                        idx,
                        Arc::new(SignedTransaction::new(public, tx.clone())),
                    ));
                } else {
                    info!(
                        "Unable to recover the public key of transaction {:?}",
                        tx.hash()
                    );
                    return Err(DecoderError::Custom(
                        "Cannot recover public key",
                    ));
                }
            }
        } else {
            let tx_num = uncached_trans.len();
            let tx_num_per_worker = tx_num / WORKER_COMPUTATION_PARALLELISM;
            let mut remainder =
                tx_num - (tx_num_per_worker * WORKER_COMPUTATION_PARALLELISM);
            let mut start_idx = 0;
            let mut end_idx = 0;
            let mut unsigned_trans = Vec::new();

            for tx in uncached_trans {
                if start_idx == end_idx {
                    // a new segment of transactions
                    end_idx = start_idx + tx_num_per_worker;
                    if remainder > 0 {
                        end_idx += 1;
                        remainder -= 1;
                    }
                    let unsigned_txes = Vec::new();
                    unsigned_trans.push(unsigned_txes);
                }

                unsigned_trans.last_mut().unwrap().push(tx);

                start_idx += 1;
            }

            let (sender, receiver) = channel();
            let n_thread = unsigned_trans.len();
            for unsigned_txes in unsigned_trans {
                RECOVER_PUB_KEY_QUEUE.enqueue(unsigned_txes.len());
                let sender = sender.clone();
                self.worker_pool.lock().execute(move || {
                    let mut signed_txes = Vec::new();
                    for (idx, tx) in unsigned_txes {
                        if let Ok(public) = tx.recover_public() {
                            signed_txes.push((idx, Arc::new(SignedTransaction::new(
                                public,
                                tx.clone(),
                            ))));
                        } else {
                            info!(
                                "Unable to recover the public key of transaction {:?}",
                                tx.hash()
                            );
                            break;
                        }
                    }
                    sender.send(signed_txes).unwrap();
                });
            }

            let mut total_recovered_num = 0 as usize;
            for tx_publics in receiver.iter().take(n_thread) {
                RECOVER_PUB_KEY_QUEUE.dequeue(tx_publics.len());
                total_recovered_num += tx_publics.len();
                for (idx, tx) in tx_publics {
                    recovered_trans.push((idx, tx));
                }
            }
            if total_recovered_num != tx_num {
                return Err(DecoderError::Custom("Cannot recover public key"));
            }
        }
        let mut tx_cache = self.tx_cache.write();
        let mut tx_cache_man = self.tx_cache_man.lock();
        for (_, tx) in &recovered_trans {
            tx_cache.insert(tx.hash(), tx.clone());
            tx_cache_man.note_used(tx.hash());
        }
        Ok(recovered_trans)
    }

    /// Find tx in tx_cache that matches tx_short_ids to fill in
    /// reconstruced_txes Return the differentially encoded index of missing
    /// transactions Now should only called once after CompactBlock is
    /// decoded
    pub fn build_partial(
        &self, compact_block: &mut CompactBlock,
    ) -> Vec<usize> {
        compact_block
            .reconstructed_txes
            .resize(compact_block.tx_short_ids.len(), None);
        let mut short_id_to_index =
            HashMap::with_capacity(compact_block.tx_short_ids.len());
        for (i, id) in compact_block.tx_short_ids.iter().enumerate() {
            short_id_to_index.insert(id, i);
        }
        let (k0, k1) =
            get_shortid_key(&compact_block.block_header, &compact_block.nonce);
        for (tx_hash, tx) in &*self.tx_cache.read() {
            let short_id = from_tx_hash(tx_hash, k0, k1);
            match short_id_to_index.remove(&short_id) {
                Some(index) => {
                    compact_block.reconstructed_txes[index] = Some(tx.clone());
                }
                None => {}
            }
        }
        let mut missing_index = Vec::new();
        for index in short_id_to_index.values() {
            missing_index.push(*index);
        }
        missing_index.sort();
        let mut last = 0;
        let mut missing_encoded = Vec::new();
        for index in missing_index {
            missing_encoded.push(index - last);
            last = index + 1;
        }
        missing_encoded
    }

    pub fn tx_cache_gc(&self) {
        let mut tx_cache = self.tx_cache.write();
        let mut tx_cache_man = self.tx_cache_man.lock();
        tx_cache_man.collect_garbage(tx_cache.len(), |ids| {
            for id in ids {
                tx_cache.remove(&id);
            }
            tx_cache.len()
        });
        tx_cache.shrink_to_fit();
    }
}
