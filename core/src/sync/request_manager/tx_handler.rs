use crate::sync::message::TransactionDigests;
use cfx_types::H256;
use metrics::{register_meter_with_group, Meter, MeterTimer};
use network::PeerId;
use primitives::{block::CompactBlock, SignedTransaction, TxPropagateId};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
lazy_static! {
    static ref TX_FIRST_MISS_METER: Arc<dyn Meter> =
        register_meter_with_group("tx_propagation", "tx_first_miss_size");
    static ref TX_FOR_COMPARE_METER: Arc<dyn Meter> =
        register_meter_with_group("tx_propagation", "tx_for_compare_size");
    static ref TX_RANDOM_BYTE_METER: Arc<dyn Meter> =
        register_meter_with_group("tx_propagation", "tx_random_byte_size");
    static ref FULL_TX_COMPARE_METER: Arc<dyn Meter> =
        register_meter_with_group("tx_propagation", "full_tx_cmpare_size");
    static ref TX_INFLIGHT_COMPARISON_METER: Arc<dyn Meter> =
        register_meter_with_group(
            "tx_propagation",
            "tx_inflight_comparison_size"
        );
    static ref REQUEST_MANAGER_PENDING_INFLIGHT_TX_TIMER: Arc<dyn Meter> =
        register_meter_with_group(
            "timer",
            "request_manager::request_pending_inflight_tx"
        );
}

struct ReceivedTransactionTimeWindowedEntry {
    pub secs: u64,
    pub tx_hashes: Vec<H256>,
}

struct ReceivedTransactionContainerInner {
    window_size: usize,
    slot_duration_as_secs: u64,
    tx_hashes_map: HashMap<TxPropagateId, HashSet<H256>>,
    tx_hashes_set: HashSet<H256>,
    time_windowed_indices: Vec<Option<ReceivedTransactionTimeWindowedEntry>>,
}

impl ReceivedTransactionContainerInner {
    pub fn new(window_size: usize, slot_duration_as_secs: u64) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }
        ReceivedTransactionContainerInner {
            window_size,
            slot_duration_as_secs,
            tx_hashes_map: HashMap::new(),
            tx_hashes_set: HashSet::new(),
            time_windowed_indices,
        }
    }
}

pub struct ReceivedTransactionContainer {
    inner: ReceivedTransactionContainerInner,
}

impl ReceivedTransactionContainer {
    const BUCKET_LIMIT: usize = 10;
    const RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE: usize = 64;

    pub fn new(timeout: u64) -> Self {
        let slot_duration_as_secs =
            timeout / ReceivedTransactionContainer::RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE as u64;
        ReceivedTransactionContainer {
            inner: ReceivedTransactionContainerInner::new(
                ReceivedTransactionContainer::RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE,
                slot_duration_as_secs,
            ),
        }
    }

    pub fn group_overflow(&self, fixed_bytes: &TxPropagateId) -> bool {
        if let Some(set) = self.inner.tx_hashes_map.get(&fixed_bytes) {
            return set.len() >= ReceivedTransactionContainer::BUCKET_LIMIT;
        }
        false
    }

    pub fn group_overflow_from_tx_hash(&self, full_trans_id: &H256) -> bool {
        let key: TxPropagateId = TransactionDigests::to_u24(
            full_trans_id[29],
            full_trans_id[30],
            full_trans_id[31],
        );
        self.group_overflow(&key)
    }

    pub fn contains_short_id(
        &self, fixed_bytes: TxPropagateId, random_byte: u8, key1: u64,
        key2: u64,
    ) -> bool
    {
        let inner = &self.inner;
        TX_FOR_COMPARE_METER.mark(1);

        match inner.tx_hashes_map.get(&fixed_bytes) {
            Some(set) => {
                TX_FIRST_MISS_METER.mark(1);
                for value in set {
                    if TransactionDigests::get_random_byte(value, key1, key2)
                        == random_byte
                    {
                        TX_RANDOM_BYTE_METER.mark(1);
                        return true;
                    }
                }
            }
            None => {}
        }
        false
    }

    pub fn contains_tx_hash(&self, tx_hash: &H256) -> bool {
        FULL_TX_COMPARE_METER.mark(1);
        self.inner.tx_hashes_set.contains(tx_hash)
    }

    pub fn get_length(&self) -> usize { self.inner.tx_hashes_map.len() }

    pub fn append_transactions(
        &mut self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        let inner = &mut self.inner;

        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH);
        let secs = duration.ok().unwrap().as_secs();
        let window_index =
            (secs / inner.slot_duration_as_secs) as usize % inner.window_size;

        let entry = if inner.time_windowed_indices[window_index].is_none() {
            inner.time_windowed_indices[window_index] =
                Some(ReceivedTransactionTimeWindowedEntry {
                    secs,
                    tx_hashes: Vec::new(),
                });
            inner.time_windowed_indices[window_index].as_mut().unwrap()
        } else {
            let indices_with_time =
                inner.time_windowed_indices[window_index].as_mut().unwrap();
            if indices_with_time.secs + inner.slot_duration_as_secs <= secs {
                for tx_hash in &indices_with_time.tx_hashes {
                    let key = TransactionDigests::to_u24(
                        tx_hash[29],
                        tx_hash[30],
                        tx_hash[31],
                    );
                    if let Some(set) = inner.tx_hashes_map.get_mut(&key) {
                        // if there is a value asscicated with the key
                        if set.len() == 1 {
                            inner.tx_hashes_map.remove(&key);
                        } else {
                            set.remove(tx_hash);
                        }
                        inner.tx_hashes_set.remove(tx_hash);
                    }
                }
                indices_with_time.secs = secs;
                indices_with_time.tx_hashes = Vec::new();
            }
            indices_with_time
        };

        for transaction in transactions {
            let tx_hash = transaction.hash();
            let short_id = TransactionDigests::to_u24(
                tx_hash[29],
                tx_hash[30],
                tx_hash[31],
            ); //read the last three bytes
            inner
                .tx_hashes_map
                .entry(short_id)
                .and_modify(|s| {
                    s.insert(tx_hash.clone());
                })
                .or_insert_with(|| {
                    let mut set = HashSet::new();
                    set.insert(tx_hash.clone());
                    set
                }); //if occupied, append, else, insert.

            inner.tx_hashes_set.insert(tx_hash.clone());
            entry.tx_hashes.push(tx_hash);
        }
    }
}

struct SentTransactionContainerInner {
    window_size: usize,
    base_time_tick: usize,
    next_time_tick: usize,
    time_windowed_indices: Vec<Option<Vec<Arc<SignedTransaction>>>>,
}

impl SentTransactionContainerInner {
    pub fn new(window_size: usize) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }

        SentTransactionContainerInner {
            window_size,
            base_time_tick: 0,
            next_time_tick: 0,
            time_windowed_indices,
        }
    }
}

/// This struct is not implemented as thread-safe since
/// currently it is only used under protection of lock
/// on SynchronizationState. Later we may refine the
/// locking design to make it thread-safe.
pub struct SentTransactionContainer {
    inner: SentTransactionContainerInner,
}

impl SentTransactionContainer {
    pub fn new(window_size: usize) -> Self {
        SentTransactionContainer {
            inner: SentTransactionContainerInner::new(window_size),
        }
    }

    pub fn get_transaction(
        &self, window_index: usize, index: usize,
    ) -> Option<Arc<SignedTransaction>> {
        let inner = &self.inner;
        if window_index >= inner.base_time_tick {
            if window_index - inner.base_time_tick >= inner.window_size {
                return None;
            }
        } else {
            if window_index + 1 + std::usize::MAX - inner.base_time_tick
                >= inner.window_size
            {
                return None;
            }
        }

        let transactions = inner.time_windowed_indices
            [window_index % inner.window_size]
            .as_ref();
        if transactions.is_none() {
            return None;
        }

        let transactions = transactions.unwrap();
        if index >= transactions.len() {
            return None;
        }

        Some(transactions[index].clone())
    }

    pub fn append_transactions(
        &mut self, transactions: Vec<Arc<SignedTransaction>>,
    ) -> usize {
        let inner = &mut self.inner;

        let base_window_index = inner.base_time_tick % inner.window_size;
        let next_time_tick = inner.next_time_tick;
        let next_window_index = next_time_tick % inner.window_size;
        inner.time_windowed_indices[next_window_index] = Some(transactions);
        if (next_window_index + 1) % inner.window_size == base_window_index {
            inner.base_time_tick += 1;
        }
        inner.next_time_tick += 1;
        next_time_tick
    }
}

struct InflightPendingTransactionTimeWindowedEntry {
    pub secs: u64,
    pub items: Vec<Arc<InflightPendingTrasnactionItem>>,
}
#[derive(Eq, PartialEq, Hash)]
pub struct InflightPendingTrasnactionItem {
    pub fixed_byte_part: TxPropagateId,
    pub random_byte_part: u8,
    pub window_index: usize,
    pub key1: u64,
    pub key2: u64,
    pub index: usize,
    pub peer_id: PeerId,
}
impl InflightPendingTrasnactionItem {
    pub fn new(
        fixed_byte_part: TxPropagateId, random_byte_part: u8,
        window_index: usize, key1: u64, key2: u64, index: usize,
        peer_id: PeerId,
    ) -> Self
    {
        InflightPendingTrasnactionItem {
            fixed_byte_part,
            random_byte_part,
            window_index,
            key1,
            key2,
            index,
            peer_id,
        }
    }
}

struct InflightPendingTransactionContainerInner {
    window_size: usize,
    slot_duration_as_secs: u64,
    txid_hashmap:
        HashMap<TxPropagateId, HashSet<Arc<InflightPendingTrasnactionItem>>>,
    time_windowed_indices:
        Vec<Option<InflightPendingTransactionTimeWindowedEntry>>,
}

impl InflightPendingTransactionContainerInner {
    pub fn new(window_size: usize, slot_duration_as_secs: u64) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }
        InflightPendingTransactionContainerInner {
            window_size,
            slot_duration_as_secs,
            txid_hashmap: HashMap::new(),
            time_windowed_indices,
        }
    }
}

pub struct InflightPendingTransactionContainer {
    inner: InflightPendingTransactionContainerInner,
}

impl InflightPendingTransactionContainer {
    const INFLIGHT_PENDING_TRANSACTION_CONTAINER_WINDOW_SIZE: usize = 5;

    pub fn new(timeout: u64) -> Self {
        let slot_duration_as_secs =
            timeout / InflightPendingTransactionContainer::INFLIGHT_PENDING_TRANSACTION_CONTAINER_WINDOW_SIZE as u64;
        InflightPendingTransactionContainer {
            inner: InflightPendingTransactionContainerInner::new(
                InflightPendingTransactionContainer::INFLIGHT_PENDING_TRANSACTION_CONTAINER_WINDOW_SIZE,
                slot_duration_as_secs,
            ),
        }
    }

    pub fn generate_tx_requests_from_inflight_pending_pool(
        &mut self, signed_transactions: &Vec<Arc<SignedTransaction>>,
    ) -> (
        Vec<Arc<InflightPendingTrasnactionItem>>,
        HashSet<TxPropagateId>,
    ) {
        let _timer = MeterTimer::time_func(
            REQUEST_MANAGER_PENDING_INFLIGHT_TX_TIMER.as_ref(),
        );
        let mut requests = vec![];
        let mut keeped_short_inflight_keys = HashSet::new();
        for tx in signed_transactions {
            let hash = tx.hash;
            let fixed_bytes_part =
                TransactionDigests::to_u24(hash[29], hash[30], hash[31]);
            match self.inner.txid_hashmap.get_mut(&fixed_bytes_part) {
                Some(set) => {
                    set.retain(|item| {
                        TransactionDigests::get_random_byte(
                            &hash, item.key1, item.key2,
                        ) != item.random_byte_part
                    });
                    if set.len() == 0 {
                        self.inner.txid_hashmap.remove(&fixed_bytes_part);
                    } else {
                        for item in set.iter() {
                            requests.push(item.clone());
                            break;
                        }
                        if let Some(last) = requests.last() {
                            keeped_short_inflight_keys
                                .insert(last.fixed_byte_part);
                            set.remove(&last.clone());
                        }
                        if set.len() == 0 {
                            self.inner.txid_hashmap.remove(&fixed_bytes_part);
                        }
                    }
                }
                None => {}
            }
        }
        (requests, keeped_short_inflight_keys)
    }

    pub fn append_inflight_pending_items(
        &mut self, items: Vec<InflightPendingTrasnactionItem>,
    ) {
        let inner = &mut self.inner;

        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH);
        let secs = duration.ok().unwrap().as_secs();
        let window_index =
            (secs / inner.slot_duration_as_secs) as usize % inner.window_size;

        let entry = if inner.time_windowed_indices[window_index].is_none() {
            inner.time_windowed_indices[window_index] =
                Some(InflightPendingTransactionTimeWindowedEntry {
                    secs,
                    items: Vec::new(),
                });
            inner.time_windowed_indices[window_index].as_mut().unwrap()
        } else {
            let indices_with_time =
                inner.time_windowed_indices[window_index].as_mut().unwrap();
            if indices_with_time.secs + inner.slot_duration_as_secs <= secs {
                for item in &indices_with_time.items {
                    if let Some(set) =
                        inner.txid_hashmap.get_mut(&item.fixed_byte_part)
                    {
                        //TODO: if this section executed, it means the node has
                        // not received the corresponding tx responses. this
                        // should be handled by either disconnected the node
                        // or making another request from a random inflight
                        // pending item.
                        if set.len() == 1 {
                            inner.txid_hashmap.remove(&item.fixed_byte_part);
                        } else {
                            set.remove(item);
                        }
                    }
                }
                indices_with_time.secs = secs;
                indices_with_time.items = Vec::new();
            }
            indices_with_time
        };

        for item in items {
            let key = item.fixed_byte_part;
            let inflight_pending_item = Arc::new(item);
            inner
                .txid_hashmap
                .entry(key)
                .and_modify(|s| {
                    s.insert(inflight_pending_item.clone());
                })
                .or_insert_with(|| {
                    let mut set = HashSet::new();
                    set.insert(inflight_pending_item.clone());
                    set
                }); //if occupied, append, else, insert.

            entry.items.push(inflight_pending_item);
        }
    }
}

struct TransactionCacheTimeWindowedEntry {
    pub secs: u64,
    pub tx_hashes: Vec<H256>,
}

struct TransactionCacheContainerInner {
    window_size: usize,
    slot_duration_as_secs: u64,
    tx_hashes_map: HashMap<u32, HashSet<H256>>,
    tx_map: HashMap<H256, Arc<SignedTransaction>>,
    time_windowed_indices: Vec<Option<TransactionCacheTimeWindowedEntry>>,
}

impl TransactionCacheContainerInner {
    pub fn new(window_size: usize, slot_duration_as_secs: u64) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }
        TransactionCacheContainerInner {
            window_size,
            slot_duration_as_secs,
            tx_hashes_map: HashMap::new(),
            tx_map: HashMap::new(),
            time_windowed_indices,
        }
    }
}

pub struct TransactionCacheContainer {
    inner: TransactionCacheContainerInner,
}

impl TransactionCacheContainer {
    const TRANSACTION_CACHE_CONTAINER_WINDOW_SIZE: usize = 64;

    pub fn new(timeout: u64) -> Self {
        let slot_duration_as_secs = timeout
            / TransactionCacheContainer::TRANSACTION_CACHE_CONTAINER_WINDOW_SIZE
                as u64;
        TransactionCacheContainer {
            inner: TransactionCacheContainerInner::new(
                TransactionCacheContainer::TRANSACTION_CACHE_CONTAINER_WINDOW_SIZE,
                slot_duration_as_secs,
            ),
        }
    }

    pub fn contains_key(&self, tx_hash: &H256) -> bool {
        self.inner.tx_map.contains_key(tx_hash)
    }

    pub fn get(&self, tx_hash: &H256) -> Option<&Arc<SignedTransaction>> {
        self.inner.tx_map.get(tx_hash)
    }

    pub fn get_transaction(
        &self, fixed_bytes: u32, random_bytes: u16, key1: u64, key2: u64,
    ) -> Option<Arc<SignedTransaction>> {
        let inner = &self.inner;
        let mut tx = None;
        match inner.tx_hashes_map.get(&fixed_bytes) {
            Some(set) => {
                for value in set {
                    if CompactBlock::get_random_bytes(value, key1, key2)
                        == random_bytes
                    {
                        if tx.is_none() {
                            tx = Some(self.get(value).unwrap().clone());
                        } else {
                            return None;
                        }
                    }
                }
            }
            None => {}
        }
        tx
    }

    pub fn append_transactions(
        &mut self, transactions: &Vec<(usize, Arc<SignedTransaction>)>,
    ) {
        let inner = &mut self.inner;

        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH);
        let secs = duration.ok().unwrap().as_secs();
        let window_index =
            (secs / inner.slot_duration_as_secs) as usize % inner.window_size;

        let entry = if inner.time_windowed_indices[window_index].is_none() {
            inner.time_windowed_indices[window_index] =
                Some(TransactionCacheTimeWindowedEntry {
                    secs,
                    tx_hashes: Vec::new(),
                });
            inner.time_windowed_indices[window_index].as_mut().unwrap()
        } else {
            let indices_with_time =
                inner.time_windowed_indices[window_index].as_mut().unwrap();
            if indices_with_time.secs + inner.slot_duration_as_secs <= secs {
                for tx_hash in &indices_with_time.tx_hashes {
                    let key = CompactBlock::to_u32(
                        tx_hash[28],
                        tx_hash[29],
                        tx_hash[30],
                        tx_hash[31],
                    );

                    if let Some(set) = inner.tx_hashes_map.get_mut(&key) {
                        // if there is a value asscicated with the key
                        if set.len() == 1 {
                            inner.tx_hashes_map.remove(&key);
                        } else {
                            set.remove(tx_hash);
                        }
                        inner.tx_map.remove(tx_hash);
                    }
                }
                indices_with_time.secs = secs;
                indices_with_time.tx_hashes = Vec::new();
            }
            indices_with_time
        };

        for (_, transaction) in transactions {
            let tx_hash = transaction.hash();
            let short_id = CompactBlock::to_u32(
                tx_hash[28],
                tx_hash[29],
                tx_hash[30],
                tx_hash[31],
            );
            inner
                .tx_hashes_map
                .entry(short_id)
                .and_modify(|s| {
                    s.insert(tx_hash.clone());
                })
                .or_insert_with(|| {
                    let mut set = HashSet::new();
                    set.insert(tx_hash.clone());
                    set
                }); //if occupied, append, else, insert.
            inner.tx_map.insert(tx_hash.clone(), transaction.clone());
            entry.tx_hashes.push(tx_hash);
        }
    }
}
