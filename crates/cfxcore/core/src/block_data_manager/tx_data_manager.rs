use crate::{
    sync::request_manager::tx_handler::TransactionCacheContainer,
    WORKER_COMPUTATION_PARALLELISM,
};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use metrics::{register_queue, Queue};
use parking_lot::{Mutex, RwLock};
use primitives::{
    block::CompactBlock, Block, SignedTransaction, TransactionWithSignature,
};
use rlp::DecoderError;
use std::{
    sync::{mpsc::channel, Arc},
    time::Duration,
};
use threadpool::ThreadPool;

lazy_static! {
    static ref RECOVER_PUB_KEY_QUEUE: Arc<dyn Queue> =
        register_queue("recover_public_key_queue");
}

pub struct TransactionDataManager {
    tx_time_window: RwLock<TransactionCacheContainer>,
    worker_pool: Arc<Mutex<ThreadPool>>,
}

impl MallocSizeOf for TransactionDataManager {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.tx_time_window.read().size_of(ops)
    }
}

impl TransactionDataManager {
    pub fn new(
        tx_cache_index_maintain_timeout: Duration,
        worker_pool: Arc<Mutex<ThreadPool>>,
    ) -> Self {
        Self {
            tx_time_window: RwLock::new(TransactionCacheContainer::new(
                tx_cache_index_maintain_timeout.as_secs(),
            )),
            worker_pool,
        }
    }

    /// Recover the public keys for uncached transactions in `transactions`.
    /// If a tx is already in the cache, it will be ignored and not included in
    /// the output vec.
    pub fn recover_unsigned_tx(
        &self, transactions: &Vec<TransactionWithSignature>,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError> {
        let uncached_trans = {
            let tx_time_window = self.tx_time_window.read();
            transactions
                .iter()
                .filter(|tx| {
                    let tx_hash = tx.hash();
                    let inserted = tx_time_window.contains_key(&tx_hash);
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
    /// The sender and public key are always re-derived from each
    /// transaction's signature. Any `sender`/`public` metadata in the input
    /// (e.g. from a `GetBlocksWithPublicResponse`) is untrusted and ignored:
    /// `sender` is an independent RLP field the signature does not bind, so
    /// trusting it would let a peer attribute a validly-signed transaction to
    /// an attacker-chosen sender. `block` is left unchanged on error.
    pub fn recover_block(&self, block: &mut Block) -> Result<(), DecoderError> {
        let (uncached_trans, mut recovered_trans) = {
            let tx_time_window = self.tx_time_window.read();
            let mut uncached_trans = Vec::new();
            let mut recovered_trans = Vec::new();
            for (idx, transaction) in block.transactions.iter().enumerate() {
                let tx_hash = transaction.hash();
                // Sample 1/128 transactions
                if tx_hash[0] & 254 == 0 {
                    debug!("Sampled transaction {:?} in block", tx_hash);
                }
                match tx_time_window.get(&tx_hash) {
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
            let tx_time_window = self.tx_time_window.read();
            let mut uncached_trans = Vec::new();
            let mut recovered_trans = Vec::new();
            for (idx, transaction) in transactions.iter().enumerate() {
                let tx_hash = transaction.hash();
                // Sample 1/128 transactions
                if tx_hash[0] & 254 == 0 {
                    debug!("Sampled transaction {:?} in block", tx_hash);
                }
                match tx_time_window.get(&tx_hash) {
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
    /// Note that we release `tx_time_window` lock during pubkey recovery to
    /// allow more parallelism, but we may recover a tx twice if it is
    /// received again before the recovery finishes.
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
                    let unsigned_txns = Vec::new();
                    unsigned_trans.push(unsigned_txns);
                }

                unsigned_trans.last_mut().unwrap().push(tx);

                start_idx += 1;
            }

            let (sender, receiver) = channel();
            let n_thread = unsigned_trans.len();
            for unsigned_txns in unsigned_trans {
                RECOVER_PUB_KEY_QUEUE.enqueue(unsigned_txns.len());
                let sender = sender.clone();
                self.worker_pool.lock().execute(move || {
                    let mut signed_txns = Vec::new();
                    for (idx, tx) in unsigned_txns {
                        if let Ok(public) = tx.recover_public() {
                            signed_txns.push((idx, Arc::new(SignedTransaction::new(
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
                    sender.send(signed_txns).unwrap();
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
        let mut tx_time_window = self.tx_time_window.write();
        tx_time_window.append_transactions(&recovered_trans.clone());
        Ok(recovered_trans)
    }

    /// Find tx in tx_time_window that matches tx_short_ids to fill in
    /// reconstruced_txns Return the differentially encoded index of missing
    /// transactions Now should only called once after CompactBlock is
    /// decoded
    pub fn find_missing_tx_indices_encoded(
        &self, compact_block: &mut CompactBlock,
    ) -> Vec<usize> {
        compact_block
            .reconstructed_txns
            .resize(compact_block.len(), None);

        let (random_bytes_vector, fixed_bytes_vector) =
            compact_block.get_decomposed_short_ids();
        let (k0, k1) = CompactBlock::get_shortid_key(
            &compact_block.block_header,
            &compact_block.nonce,
        );
        let mut missing_index = Vec::new();
        {
            let tx_time_window = self.tx_time_window.read();
            for i in 0..fixed_bytes_vector.len() {
                match tx_time_window.get_transaction(
                    fixed_bytes_vector[i],
                    random_bytes_vector[i],
                    k0,
                    k1,
                ) {
                    Some(tx) => {
                        compact_block.reconstructed_txns[i] = Some(tx.clone());
                    }
                    None => {
                        missing_index.push(i);
                    }
                }
            }
        }

        let mut last = 0;
        let mut missing_encoded = Vec::new();
        for index in missing_index {
            missing_encoded.push(index - last);
            last = index + 1;
        }
        missing_encoded
    }
}

#[cfg(test)]
mod tests {
    use super::TransactionDataManager;
    use crate::{
        keylib::{Generator, Random},
        sync::message::GetBlocksWithPublicResponse,
    };
    use cfx_types::{AddressSpaceUtil, U256};
    use parking_lot::Mutex;
    use primitives::{
        transaction::native_transaction::NativeTransaction, Action, Block,
        BlockHeaderBuilder, Transaction,
    };
    use std::{sync::Arc, time::Duration};
    use threadpool::ThreadPool;

    /// `recover_block` must re-derive each sender from the signature, not
    /// trust the `sender`/`public` a `GetBlocksWithPublicResponse` peer
    /// supplies.
    #[test]
    fn recover_block_ignores_forged_with_public_sender() {
        let attacker = Random.generate().unwrap();
        let victim = Random.generate().unwrap();
        let recipient = Random.generate().unwrap().address();

        let mut forged = Transaction::from(NativeTransaction {
            nonce: U256::zero(),
            gas_price: U256::one(),
            gas: U256::from(21_000),
            action: Action::Call(recipient),
            value: U256::from(7),
            storage_limit: 0,
            epoch_height: 0,
            chain_id: 1,
            data: Vec::new(),
        })
        .sign(attacker.secret());

        // Forge only `sender`; the attacker's public key still matches the
        // signature, so `verify_public` cannot catch it.
        forged.sender = victim.address();
        assert!(forged.verify_public(false).unwrap());

        // Round-trip through the real with-public wire encoding.
        let response = GetBlocksWithPublicResponse {
            request_id: 1,
            blocks: vec![Block::new(
                BlockHeaderBuilder::new().build(),
                vec![Arc::new(forged)],
            )],
        };
        let decoded: GetBlocksWithPublicResponse =
            rlp::decode(&rlp::encode(&response))
                .expect("with-public response decodes");
        let mut block = decoded.blocks.into_iter().next().unwrap();

        // The forgery must survive decoding, or the test proves nothing.
        assert!(block.transactions[0].public.is_some());
        assert_eq!(
            block.transactions[0].sender(),
            victim.address().with_native_space()
        );

        let tx_manager = TransactionDataManager::new(
            Duration::from_secs(600),
            Arc::new(Mutex::new(ThreadPool::new(1))),
        );
        tx_manager
            .recover_block(&mut block)
            .expect("block transactions recover from their signatures");

        let recovered = block.transactions[0].clone();
        assert_eq!(
            recovered.sender(),
            attacker.address().with_native_space(),
            "sender must be re-derived from the signature, not the forged \
             peer-supplied metadata"
        );
    }
}
