use super::{
    deferred_pool::DeferredPool,
    garbage_collector::GarbageCollector,
    nonce_pool::{InsertResult, TxWithReadyInfo},
    pool_metrics::pool_inner_metrics::*,
    state_provider::StateProvider,
    TransactionPoolError,
};

use crate::verification::{PackingCheckResult, VerificationConfig};
use cfx_executor::machine::Machine;
use cfx_packing_pool::PackingPoolConfig;
use cfx_parameters::{
    block::cspace_block_gas_limit_after_cip1559,
    consensus_internal::ELASTICITY_MULTIPLIER,
    staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT,
};

use cfx_rpc_cfx_types::TransactionStatus;
use cfx_statedb::Result as StateDbResult;
use cfx_types::{
    address_util::AddressUtil, AddressWithSpace, Space, SpaceMap, H256, U128,
    U256, U512,
};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::MeterTimer;
use primitives::{
    block_header::compute_next_price, Account, Action, SignedTransaction,
    Transaction, TransactionWithSignature,
};
use rlp::*;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

// lazy_static! {
//     pub static ref MAX_WEIGHT: U256 = u128::max_value().into();
// }

const FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET: u32 = 2000;

#[derive(Default, DeriveMallocSizeOf)]
pub struct TransactionSet {
    inner: HashMap<H256, Arc<SignedTransaction>>,
    count: SpaceMap<usize>,
}

impl TransactionSet {
    fn get(&self, tx_hash: &H256) -> Option<&Arc<SignedTransaction>> {
        self.inner.get(tx_hash)
    }

    fn values(
        &self,
    ) -> std::collections::hash_map::Values<'_, H256, Arc<SignedTransaction>>
    {
        self.inner.values()
    }

    fn insert(
        &mut self, tx_hash: H256, tx: Arc<SignedTransaction>,
    ) -> Option<Arc<SignedTransaction>> {
        *self.count.in_space_mut(tx.space()) += 1;
        let res = self.inner.insert(tx_hash, tx);
        if let Some(ref tx) = res {
            *self.count.in_space_mut(tx.space()) -= 1;
        }
        res
    }

    fn remove(&mut self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        let res = self.inner.remove(tx_hash);
        if let Some(ref tx) = res {
            *self.count.in_space_mut(tx.space()) -= 1;
        }
        res
    }

    fn clear(&mut self) {
        self.inner.clear();
        self.count.apply_all(|x| *x = 0);
    }
}

#[derive(DeriveMallocSizeOf)]
pub struct TransactionPoolInner {
    capacity: usize,
    // deprecated, this value is never updated
    total_received_count: usize,
    unpacked_transaction_count: SpaceMap<usize>,
    /// Tracks all transactions in the transaction pool by account and nonce.
    /// Packed and executed transactions will eventually be garbage collected.
    deferred_pool: DeferredPool,
    /// The cache of the latest nonce and balance in the state.
    /// Updated with the storage data after a block is processed in consensus
    /// (set_tx_packed), after epoch execution, or during transaction
    /// insertion.
    ready_nonces_and_balances: HashMap<AddressWithSpace, (U256, U256)>,
    garbage_collector: SpaceMap<GarbageCollector>,
    /// Keeps all transactions in the transaction pool.
    /// It should contain the same transaction set as `deferred_pool`.
    txs: TransactionSet,
}

impl TransactionPoolInner {
    pub fn new(
        capacity: usize, max_packing_batch_gas_limit: usize,
        max_packing_batch_size: usize, packing_pool_degree: u8,
    ) -> Self {
        let config = PackingPoolConfig::new(
            max_packing_batch_gas_limit.into(),
            max_packing_batch_size,
            packing_pool_degree,
        );
        TransactionPoolInner {
            capacity,
            total_received_count: 0,
            unpacked_transaction_count: SpaceMap::default(),
            deferred_pool: DeferredPool::new(config),
            ready_nonces_and_balances: HashMap::new(),
            garbage_collector: SpaceMap::default(),
            txs: TransactionSet::default(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self { Self::new(50_000, 3_000_000, 50, 4) }

    pub fn clear(&mut self) {
        self.deferred_pool.clear();
        self.ready_nonces_and_balances.clear();
        self.garbage_collector.apply_all(|x| x.clear());
        self.txs.clear();
        self.total_received_count = 0;
        self.unpacked_transaction_count.apply_all(|x| *x = 0);
    }

    pub fn total_deferred(&self, space: Option<Space>) -> usize {
        match space {
            Some(space) => *self.txs.count.in_space(space),
            None => self.txs.count.map_sum(|x| *x),
        }
    }

    pub fn ready_transacton_hashes_in_evm_pool(&self) -> BTreeSet<H256> {
        self.deferred_pool
            .ready_transaction_hashes(Space::Ethereum)
            .collect()
    }

    pub fn ready_transacton_hashes_in_native_pool(&self) -> BTreeSet<H256> {
        self.deferred_pool
            .ready_transaction_hashes(Space::Native)
            .collect()
    }

    pub fn total_ready_accounts(&self) -> usize {
        self.deferred_pool.ready_account_number(Space::Ethereum)
            + self.deferred_pool.ready_account_number(Space::Native)
    }

    pub fn total_received(&self) -> usize { self.total_received_count }

    pub fn total_unpacked(&self, space: Option<Space>) -> usize {
        match space {
            Some(space) => *self.unpacked_transaction_count.in_space(space),
            None => self.unpacked_transaction_count.map_sum(|x| *x),
        }
    }

    pub fn total_pending(&self, space: Option<Space>) -> u64 {
        let get_nonce_and_balance = |addr: &AddressWithSpace| {
            self.ready_nonces_and_balances
                .get(addr)
                .map(|x| *x)
                .unwrap_or_default()
        };
        self.deferred_pool
            .pending_tx_number(space, get_nonce_and_balance)
    }

    pub fn total_queued(&self, space: Option<Space>) -> u64 {
        self.total_unpacked(space) as u64 - self.total_pending(space)
    }

    pub fn get(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.txs.get(tx_hash).map(|x| x.clone())
    }

    pub fn get_by_address2nonce(
        &self, address: AddressWithSpace, nonce: U256,
    ) -> Option<Arc<SignedTransaction>> {
        let bucket = self.deferred_pool.get_bucket(&address)?;
        bucket.get_tx_by_nonce(nonce).map(|tx| tx.transaction)
    }

    pub fn is_full(&self, space: Space) -> bool {
        return self.total_deferred(Some(space)) >= self.capacity;
    }

    pub fn get_current_timestamp(&self) -> u64 {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        since_the_epoch.as_secs()
    }

    /// A sender has a transaction which is garbage collectable if
    ///    1. there is at least a transaction whose nonce is less than
    /// `ready_nonce`
    ///    2. the nonce of all transactions are greater than or equal to
    /// `ready_nonce` and it is not garbage collected during the last
    /// `TIME_WINDOW` seconds
    ///
    /// We will pick a sender who has maximum number of transactions which are
    /// garbage collectable. And if there is a tie, the one who has minimum
    /// timestamp will be picked.
    pub fn collect_garbage(&mut self, new_tx: &SignedTransaction) {
        let space = new_tx.space();
        let count_before_gc = self.total_deferred(Some(space));
        let mut skipped_self_node = None;
        while self.is_full(space)
            && !self.garbage_collector.in_space(space).is_empty()
        {
            let current_timestamp = self.get_current_timestamp();
            let (victim_address, victim) =
                self.garbage_collector.in_space(space).top().unwrap();
            // Accounts which are not in `deferred_pool` may be inserted
            // into `garbage_collector`, we can just ignore them.
            if !self.deferred_pool.contain_address(victim_address) {
                self.garbage_collector.in_space_mut(space).pop();
                continue;
            }

            // `count == 0` means all transactions are not executed, so there is
            // no unconditional garbage collection to conduct and we need to
            // check if we should replace one unexecuted tx.
            if victim.count == 0 {
                if *victim_address == new_tx.sender() {
                    // We do not GC a not-executed transaction from the same
                    // sender, so save it and try another account.
                    let (victim_address, victim) = self
                        .garbage_collector
                        .in_space_mut(space)
                        .pop()
                        .unwrap();
                    skipped_self_node = Some((victim_address, victim));
                    continue;
                } else if victim.has_ready_tx
                    && victim.first_tx_gas_price >= *new_tx.gas_price()
                {
                    // If all transactions are not executed but some accounts
                    // are not ready to be packed, we directly replace a
                    // not-ready transaction (with the least gas_price in
                    // garbage_collector). If all accounts
                    // are ready, we check if the new tx has larger gas price
                    // than some.
                    trace!("txpool::collect_garbage fails, victim={:?} new_tx={:?} \
                    new_tx_gas_price={:?}", victim, new_tx.hash(), new_tx.gas_price());
                    return;
                }
            }

            // victim is now chosen to be evicted.
            let (victim_address, victim) =
                self.garbage_collector.in_space_mut(space).pop().unwrap();

            let (ready_nonce, _) = self
                .get_local_nonce_and_balance(&victim_address)
                .unwrap_or((0.into(), 0.into()));

            let tx_with_ready_info = self
                .deferred_pool
                .remove_lowest_nonce(&victim_address)
                .unwrap();
            let to_remove_tx = tx_with_ready_info.get_arc_tx().clone();

            // We have to garbage collect an unexecuted transaction.
            // TODO: Implement more heuristic strategies
            if *to_remove_tx.nonce() >= ready_nonce {
                assert_eq!(victim.count, 0);
                GC_UNEXECUTED_COUNTER.inc(1);
                warn!("an unexecuted tx is garbage-collected.");
            }

            if !tx_with_ready_info.is_already_packed() {
                let tx_space = tx_with_ready_info.space();
                *self.unpacked_transaction_count.in_space_mut(tx_space) = self
                    .unpacked_transaction_count
                    .in_space(tx_space)
                    .checked_sub(1)
                    .unwrap_or_else(|| {
                        error!("unpacked_transaction_count under-flows.");
                        0
                    });
            }

            // maintain ready info
            if !self.deferred_pool.contain_address(&victim_address) {
                self.ready_nonces_and_balances.remove(&victim_address);
            // The picked sender has no transactions now, and has been popped
            // from `garbage_collector`.
            } else {
                let has_ready_tx =
                    self.deferred_pool.has_ready_tx(&victim_address);
                let first_tx_gas_price = *self
                    .deferred_pool
                    .get_lowest_nonce_tx(&victim_address)
                    .expect("addr exist")
                    .gas_price();
                let count = if victim.count > 0 {
                    victim.count - 1
                } else {
                    0
                };
                self.garbage_collector.in_space_mut(space).insert(
                    &victim_address,
                    count,
                    current_timestamp,
                    has_ready_tx,
                    first_tx_gas_price,
                );
            }

            // maintain txs
            self.txs.remove(&to_remove_tx.hash());
        }

        // Insert back skipped nodes to keep `garbage_collector`
        // unchanged.
        if let Some((addr, node)) = skipped_self_node {
            self.garbage_collector.in_space_mut(space).insert(
                &addr,
                node.count,
                node.timestamp,
                node.has_ready_tx,
                node.first_tx_gas_price,
            );
        }
        GC_METER.mark(count_before_gc - self.total_deferred(Some(space)));
    }

    /// Collect garbage and return the remaining quota of the pool to insert new
    /// transactions.
    pub fn remaining_quota(&self) -> usize {
        let len = self.total_deferred(None);
        self.garbage_collector.size() * self.capacity - len
            + self.garbage_collector.map_sum(|x| x.gc_size())
    }

    pub fn capacity(&self) -> usize { self.capacity }

    #[cfg(test)]
    fn insert_transaction_for_test(
        &mut self, transaction: Arc<SignedTransaction>, sender_nonce: U256,
    ) -> InsertResult {
        let sender = transaction.sender();
        let res = self.insert_transaction_without_readiness_check(
            transaction,
            false,
            true,
            (sender_nonce, U256::from(u64::MAX)),
            (0.into(), 0),
        );
        self.recalculate_readiness(&sender, sender_nonce, U256::from(u64::MAX));
        res
    }

    // the new inserting will fail if tx_pool is full (even if `force` is true)
    fn insert_transaction_without_readiness_check(
        &mut self, transaction: Arc<SignedTransaction>, packed: bool,
        force: bool, state_nonce_and_balance: (U256, U256),
        (sponsored_gas, sponsored_storage): (U256, u64),
    ) -> InsertResult {
        let _timer = MeterTimer::time_func(
            TX_POOL_INNER_WITHOUTCHECK_INSERT_TIMER.as_ref(),
        );
        if !self.deferred_pool.check_sender_and_nonce_exists(
            &transaction.sender(),
            &transaction.nonce(),
        ) {
            self.collect_garbage(transaction.as_ref());
            if self.is_full(transaction.space()) {
                return InsertResult::Failed(TransactionPoolError::TxPoolFull);
            }
        }
        let result = {
            let _timer =
                MeterTimer::time_func(DEFERRED_POOL_INNER_INSERT.as_ref());
            self.deferred_pool.insert(
                TxWithReadyInfo::new(
                    transaction.clone(),
                    packed,
                    sponsored_gas,
                    sponsored_storage,
                ),
                force,
            )
        };

        let tx_space = transaction.space();
        match &result {
            InsertResult::NewAdded => {
                let (state_nonce, state_balance) = state_nonce_and_balance;
                self.update_nonce_and_balance(
                    &transaction.sender(),
                    state_nonce,
                    state_balance,
                );
                // GarbageCollector will be updated by the caller.
                self.txs.insert(transaction.hash(), transaction.clone());
                if !packed {
                    *self.unpacked_transaction_count.in_space_mut(tx_space) +=
                        1;
                }
            }
            InsertResult::Failed(_) => {}
            InsertResult::Updated(replaced_tx) => {
                if !replaced_tx.is_already_packed() {
                    *self.unpacked_transaction_count.in_space_mut(tx_space) =
                        self.unpacked_transaction_count
                            .in_space(tx_space)
                            .checked_sub(1)
                            .unwrap_or_else(|| {
                                error!(
                                    "unpacked_transaction_count under-flows."
                                );
                                0
                            });
                }
                self.txs.remove(&replaced_tx.hash());
                self.txs.insert(transaction.hash(), transaction.clone());
                if !packed {
                    *self.unpacked_transaction_count.in_space_mut(tx_space) +=
                        1;
                }
            }
        }

        result
    }

    #[allow(dead_code)]
    fn mark_packed(&mut self, tx: &SignedTransaction, packed: bool) {
        let changed =
            self.deferred_pool
                .mark_packed(tx.sender(), tx.nonce(), packed);
        if changed {
            let tx_space = tx.space();
            if packed {
                if *self.unpacked_transaction_count.in_space(tx_space) == 0 {
                    error!("unpacked_transaction_count under-flows.");
                } else {
                    *self.unpacked_transaction_count.in_space_mut(tx_space) -=
                        1;
                }
            } else {
                *self.unpacked_transaction_count.in_space_mut(tx_space) += 1;
            }
        }
    }

    pub fn get_account_pending_info(
        &self, address: &AddressWithSpace,
    ) -> Option<(U256, U256, U256, H256)> {
        let (local_nonce, _local_balance) = self
            .get_local_nonce_and_balance(address)
            .unwrap_or((U256::from(0), U256::from(0)));
        match self.deferred_pool.get_pending_info(address, &local_nonce) {
            Some((pending_count, pending_tx)) => Some((
                local_nonce,
                U256::from(pending_count),
                *pending_tx.nonce(),
                pending_tx.hash(),
            )),
            None => {
                Some((local_nonce, U256::from(0), U256::from(0), H256::zero()))
            }
        }
    }

    pub fn get_account_pending_transactions(
        &self, address: &AddressWithSpace, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<usize>,
    ) -> (
        Vec<Arc<SignedTransaction>>,
        Option<TransactionStatus>,
        usize,
    ) {
        let (local_nonce, local_balance) = self
            .get_local_nonce_and_balance(address)
            .unwrap_or((U256::from(0), U256::from(0)));
        let start_nonce = maybe_start_nonce.unwrap_or(local_nonce);
        let (pending_txs, pending_reason) =
            self.deferred_pool.get_pending_transactions(
                address,
                &start_nonce,
                &local_nonce,
                &local_balance,
            );
        if pending_txs.is_empty() {
            return (Vec::new(), None, 0);
        }
        let first_tx_status = match pending_reason {
            None => TransactionStatus::Ready,
            Some(reason) => TransactionStatus::Pending(reason),
        };
        let pending_count = pending_txs.len();
        let limit = maybe_limit.unwrap_or(usize::MAX);
        (
            pending_txs
                .into_iter()
                .map(|x| x.transaction.clone())
                .take(limit)
                .collect(),
            Some(first_tx_status),
            pending_count,
        )
    }

    pub fn get_local_nonce_and_balance(
        &self, address: &AddressWithSpace,
    ) -> Option<(U256, U256)> {
        self.ready_nonces_and_balances.get(address).map(|x| *x)
    }

    fn update_nonce_and_balance(
        &mut self, address: &AddressWithSpace, nonce: U256, balance: U256,
    ) {
        if !self.deferred_pool.contain_address(address) {
            return;
        }
        self.ready_nonces_and_balances
            .insert((*address).clone(), (nonce, balance));
    }

    fn get_and_update_nonce_and_balance_from_storage(
        &mut self, address: &AddressWithSpace, state: &StateProvider,
    ) -> StateDbResult<(U256, U256)> {
        let nonce_and_balance = state.get_nonce_and_balance(address)?;
        if !self.deferred_pool.contain_address(address) {
            return Ok(nonce_and_balance);
        }
        self.ready_nonces_and_balances
            .insert((*address).clone(), nonce_and_balance);

        Ok(nonce_and_balance)
    }

    pub fn get_lowest_nonce(&self, addr: &AddressWithSpace) -> U256 {
        let mut ret = 0.into();
        if let Some((nonce, _)) = self.get_local_nonce_and_balance(addr) {
            ret = nonce;
        }
        if let Some(nonce) = self.deferred_pool.get_lowest_nonce(addr) {
            if *nonce < ret {
                ret = *nonce;
            }
        }
        ret
    }

    pub fn get_next_nonce(
        &self, address: &AddressWithSpace, state_nonce: U256,
    ) -> U256 {
        self.deferred_pool
            .last_succ_nonce(*address, state_nonce)
            .unwrap_or(state_nonce)
    }

    #[allow(dead_code)]
    fn recalculate_readiness_with_local_info(
        &mut self, addr: &AddressWithSpace,
    ) {
        let (nonce, balance) = self
            .get_local_nonce_and_balance(addr)
            .unwrap_or((0.into(), 0.into()));
        self.recalculate_readiness(addr, nonce, balance);
    }

    fn recalculate_readiness_with_fixed_info(
        &mut self, addr: &AddressWithSpace, nonce: U256, balance: U256,
    ) {
        self.update_nonce_and_balance(addr, nonce, balance);
        self.recalculate_readiness(addr, nonce, balance);
    }

    fn recalculate_readiness_with_state(
        &mut self, addr: &AddressWithSpace, account_cache: &StateProvider,
    ) -> StateDbResult<()> {
        let _timer = MeterTimer::time_func(TX_POOL_RECALCULATE.as_ref());
        let (nonce, balance) = self
            .get_and_update_nonce_and_balance_from_storage(
                addr,
                account_cache,
            )?;
        self.recalculate_readiness(addr, nonce, balance);
        Ok(())
    }

    fn recalculate_readiness(
        &mut self, addr: &AddressWithSpace, nonce: U256, balance: U256,
    ) {
        let space = addr.space;
        let ret = self
            .deferred_pool
            .recalculate_readiness_with_local_info(addr, nonce, balance);
        // If addr is not in `deferred_pool`, it should have also been removed
        // from garbage_collector
        if let Some(tx) = self.deferred_pool.get_lowest_nonce_tx(addr) {
            let count = self.deferred_pool.count_less(addr, &nonce);
            let timestamp = self
                .garbage_collector
                .in_space(space)
                .get_timestamp(addr)
                .unwrap_or(self.get_current_timestamp());
            self.garbage_collector.in_space_mut(space).insert(
                addr,
                count,
                timestamp,
                ret.is_some(),
                *tx.gas_price(),
            );
        } else {
            // An account is only removed from `deferred_pool` in GC,
            // so this is not likely to happen.
            // One possible reason is that an transactions not in txpool is
            // executed and passed to notify_modified_accounts.
            debug!(
                "recalculate_readiness called for missing account: addr={:?}",
                addr
            );
        }
    }

    pub fn check_tx_packed_in_deferred_pool(&self, tx_hash: &H256) -> bool {
        match self.txs.get(tx_hash) {
            Some(tx) => {
                self.deferred_pool.check_tx_packed(tx.sender(), *tx.nonce())
            }
            None => false,
        }
    }

    /// pack at most num_txs transactions randomly
    pub fn pack_transactions<'a>(
        &mut self, num_txs: usize, block_gas_limit: U256, evm_gas_limit: U256,
        block_size_limit: usize, best_epoch_height: u64,
        best_block_number: u64, verification_config: &VerificationConfig,
        machine: &Machine,
    ) -> Vec<Arc<SignedTransaction>> {
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return packed_transactions;
        }

        let spec = machine.spec(best_block_number, best_epoch_height);
        let transitions = &machine.params().transition_heights;

        let validity = |tx: &SignedTransaction| {
            verification_config.fast_recheck(
                tx,
                best_epoch_height,
                transitions,
                &spec,
            )
        };

        let (sampled_tx, used_gas, used_size) =
            self.deferred_pool.packing_sampler(
                Space::Ethereum,
                std::cmp::min(block_gas_limit, evm_gas_limit),
                block_size_limit,
                num_txs,
                U256::zero(),
                validity,
            );
        packed_transactions.extend_from_slice(&sampled_tx);

        let (sampled_tx, _, _) = self.deferred_pool.packing_sampler(
            Space::Native,
            block_gas_limit - used_gas,
            block_size_limit - used_size,
            num_txs - sampled_tx.len(),
            U256::zero(),
            validity,
        );
        packed_transactions.extend_from_slice(&sampled_tx);

        if log::max_level() >= log::Level::Debug {
            let mut rlp_s = RlpStream::new();
            for tx in &packed_transactions {
                rlp_s.append::<TransactionWithSignature>(&**tx);
            }
            debug!(
                "After packing packed_transactions: {}, rlp size: {}",
                packed_transactions.len(),
                rlp_s.out().len(),
            );
        }

        packed_transactions
    }

    pub fn pack_transactions_1559<'a>(
        &mut self, num_txs: usize, block_gas_limit: U256,
        parent_base_price: SpaceMap<U256>, block_size_limit: usize,
        best_epoch_height: u64, machine: &Machine,
        validity: impl Fn(&SignedTransaction) -> PackingCheckResult,
    ) -> (Vec<Arc<SignedTransaction>>, SpaceMap<U256>) {
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return (packed_transactions, parent_base_price);
        }

        debug!(
            "Packing transaction for 1559, parent base price {:?}",
            parent_base_price
        );

        let mut block_base_price = parent_base_price.clone();

        let can_pack_evm =
            machine.params().can_pack_evm_transaction(best_epoch_height);

        let (evm_packed_tx_num, evm_used_size) = if can_pack_evm {
            let gas_target = block_gas_limit * 5 / 10 / ELASTICITY_MULTIPLIER;
            let parent_base_price = parent_base_price[Space::Ethereum];
            let min_base_price =
                machine.params().min_base_price()[Space::Ethereum];

            let (packing_gas_limit, tx_min_price) =
                self.deferred_pool.estimate_packing_gas_limit(
                    Space::Ethereum,
                    gas_target,
                    parent_base_price,
                    min_base_price,
                );
            debug!(
                "Packing plan (espace): gas limit: {:?}, tx min price: {:?}",
                packing_gas_limit, tx_min_price
            );
            let (sampled_tx, used_gas, used_size) =
                self.deferred_pool.packing_sampler(
                    Space::Ethereum,
                    packing_gas_limit,
                    block_size_limit,
                    num_txs,
                    tx_min_price,
                    &validity,
                );

            // Recompute the base price, it should be <= estimated base price,
            // since the actual used gas is <= estimated limit
            let base_price = compute_next_price(
                gas_target,
                used_gas,
                parent_base_price,
                min_base_price,
            );

            if base_price <= tx_min_price {
                debug!(
                    "Packing result (espace): gas used: {:?}, base price: {:?}",
                    used_gas, base_price
                );
                block_base_price[Space::Ethereum] = base_price;
                packed_transactions.extend_from_slice(&sampled_tx);

                (sampled_tx.len(), used_size)
            } else {
                // Should be unreachable
                warn!(
                    "Inconsistent packing result (espace): gas used: {:?}, base price: {:?}", 
                    used_gas, base_price
                );
                block_base_price[Space::Ethereum] = compute_next_price(
                    gas_target,
                    U256::zero(),
                    parent_base_price,
                    min_base_price,
                );
                (0, 0)
            }
        } else {
            (0, 0)
        };

        {
            let gas_target =
                cspace_block_gas_limit_after_cip1559(block_gas_limit)
                    / ELASTICITY_MULTIPLIER;
            let parent_base_price = parent_base_price[Space::Native];
            let min_base_price =
                machine.params().min_base_price()[Space::Native];

            let (packing_gas_limit, tx_min_price) =
                self.deferred_pool.estimate_packing_gas_limit(
                    Space::Native,
                    gas_target,
                    parent_base_price,
                    min_base_price,
                );

            debug!(
                "Packing plan (core space): gas limit: {:?}, tx min price: {:?}",
                packing_gas_limit, tx_min_price
            );

            let (sampled_tx, used_gas, _) = self.deferred_pool.packing_sampler(
                Space::Native,
                packing_gas_limit,
                block_size_limit - evm_used_size,
                num_txs - evm_packed_tx_num,
                tx_min_price,
                &validity,
            );

            // Recompute the base price, it should be <= estimated base price,
            // since the actual used gas is <= estimated limit
            let base_price = compute_next_price(
                gas_target,
                used_gas,
                parent_base_price,
                min_base_price,
            );

            if base_price <= tx_min_price {
                debug!(
                    "Packing result (core space): gas used: {:?}, base price: {:?}",
                    used_gas, base_price
                );
                block_base_price[Space::Native] = base_price;
                packed_transactions.extend_from_slice(&sampled_tx);
            } else {
                // Should be unreachable
                warn!(
                    "Inconsistent packing result (core space): gas used: {:?}, base price: {:?}", 
                    used_gas, base_price
                );
                block_base_price[Space::Native] = compute_next_price(
                    gas_target,
                    U256::zero(),
                    parent_base_price,
                    min_base_price,
                );
            }
        }

        if log::max_level() >= log::Level::Debug {
            let mut rlp_s = RlpStream::new();
            for tx in &packed_transactions {
                rlp_s.append::<TransactionWithSignature>(&**tx);
            }
            debug!(
                "After packing packed_transactions: {}, rlp size: {}",
                packed_transactions.len(),
                rlp_s.out().len(),
            );
        }

        (packed_transactions, block_base_price)
    }

    pub fn notify_modified_accounts(
        &mut self, accounts_from_execution: Vec<Account>,
    ) {
        for account in &accounts_from_execution {
            self.recalculate_readiness_with_fixed_info(
                account.address(),
                account.nonce,
                account.balance,
            );
        }
    }

    /// content retrieves the ready and deferred transactions.
    pub fn content(
        &self, address: Option<AddressWithSpace>,
    ) -> (Vec<Arc<SignedTransaction>>, Vec<Arc<SignedTransaction>>) {
        let ready_txs = match address {
            Some(addr) => self
                .deferred_pool
                .ready_transactions_by_address(addr)
                .map_or(vec![], |x| x.to_vec()),
            None => self
                .deferred_pool
                .all_ready_transactions()
                .cloned()
                .collect(),
        };

        let deferred_txs = self
            .txs
            .values()
            .filter(|tx| address == None || tx.sender() == address.unwrap())
            .map(|v| v.clone())
            .collect();

        (ready_txs, deferred_txs)
    }

    // Add transaction into deferred pool and maintain its readiness
    // the packed tag provided
    // if force tag is true, the replacement in nonce pool must be happened
    pub fn insert_transaction_with_readiness_check(
        &mut self, account_cache: &StateProvider,
        transaction: Arc<SignedTransaction>, packed: bool, force: bool,
    ) -> Result<(), TransactionPoolError> {
        let _timer = MeterTimer::time_func(TX_POOL_INNER_INSERT_TIMER.as_ref());
        let (sponsored_gas, sponsored_storage) =
            self.get_sponsored_gas_and_storage(account_cache, &transaction)?;

        let (state_nonce, state_balance) =
            account_cache.get_nonce_and_balance(&transaction.sender())?;

        if transaction.hash[0] & 254 == 0 {
            trace!(
                "Transaction {:?} sender: {:?} current nonce: {:?}, state nonce:{:?}",
                transaction.hash, transaction.sender, transaction.nonce(), state_nonce
            );
        }
        if *transaction.nonce()
            >= state_nonce
                + U256::from(FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET)
        {
            trace!(
                "Transaction {:?} is discarded due to in too distant future",
                transaction.hash()
            );
            return Err(TransactionPoolError::NonceTooDistant {
                hash: transaction.hash(),
                nonce: *transaction.nonce(),
            });
        } else if !packed /* Because we may get slightly out-dated state for transaction pool, we should allow transaction pool to set already past-nonce transactions to packed. */
            && *transaction.nonce() < state_nonce
        {
            trace!(
                "Transaction {:?} is discarded due to a too stale nonce, self.nonce()={}, state_nonce={}",
                transaction.hash(), transaction.nonce(), state_nonce,
            );
            return Err(TransactionPoolError::NonceTooStale {
                hash: transaction.hash(),
                nonce: *transaction.nonce(),
            });
        }

        // check balance
        if !packed && !force {
            let mut need_balance = U256::from(0);
            let estimate_gas_fee = Self::cal_gas_fee(
                transaction.gas().clone(),
                transaction.gas_price().clone(),
            );
            match transaction.unsigned {
                Transaction::Native(ref utx) => {
                    need_balance += utx.value().clone();
                    if sponsored_gas == U256::from(0) {
                        need_balance += estimate_gas_fee;
                    }
                    if sponsored_storage == 0 {
                        need_balance += U256::from(*utx.storage_limit())
                            * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
                    }
                }
                Transaction::Ethereum(ref utx) => {
                    need_balance += utx.value().clone();
                    need_balance += estimate_gas_fee;
                }
            }

            if need_balance > state_balance {
                let msg = format!(
                    "Transaction {:?} is discarded due to out of balance, needs {:?} but account balance is {:?}",
                    transaction.hash(),
                    need_balance,
                    state_balance
                );
                trace!("{}", msg);
                return Err(TransactionPoolError::OutOfBalance {
                    need: need_balance,
                    have: state_balance,
                    hash: transaction.hash(),
                });
            }
        }

        let result = self.insert_transaction_without_readiness_check(
            transaction.clone(),
            packed,
            force,
            (state_nonce, state_balance),
            (sponsored_gas, sponsored_storage),
        );
        if let InsertResult::Failed(err) = result {
            return Err(err);
        }

        self.recalculate_readiness_with_state(
            &transaction.sender(),
            account_cache,
        )?;

        Ok(())
    }

    fn cal_gas_fee(gas: U256, gas_price: U256) -> U256 {
        let estimated_gas_u512 = gas.full_mul(gas_price);
        // Normally, it is less than 2^128
        let estimated_gas =
            if estimated_gas_u512 > U512::from(U128::max_value()) {
                U256::from(U128::max_value())
            } else {
                gas * gas_price
            };
        estimated_gas
    }

    pub fn get_sponsored_gas_and_storage(
        &self, account_cache: &StateProvider, transaction: &SignedTransaction,
    ) -> StateDbResult<(U256, u64)> {
        let sender = transaction.sender();

        // Filter out espace transactions
        let utx = if let Transaction::Native(ref utx) = transaction.unsigned {
            utx
        } else {
            return Ok(Default::default());
        };

        // Keep contract call only
        let contract_address = match utx.action() {
            Action::Call(callee) if callee.is_contract_address() => *callee,
            _ => {
                return Ok(Default::default());
            }
        };

        // Get sponsor info
        let sponsor_info = if let Some(sponsor_info) =
            account_cache.get_sponsor_info(&contract_address)?
        {
            sponsor_info
        } else {
            return Ok(Default::default());
        };

        // Check if sender is eligible for sponsor
        if !account_cache
            .check_commission_privilege(&contract_address, &sender.address)?
        {
            return Ok(Default::default());
        }

        // Detailed logics
        let estimated_gas = Self::cal_gas_fee(
            transaction.gas().clone(),
            transaction.gas_price().clone(),
        );
        let sponsored_gas = if estimated_gas <= sponsor_info.sponsor_gas_bound
            && estimated_gas <= sponsor_info.sponsor_balance_for_gas
        {
            utx.gas().clone()
        } else {
            0.into()
        };

        let estimated_collateral = U256::from(*utx.storage_limit())
            * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
        let sponsored_collateral = if estimated_collateral
            <= sponsor_info.sponsor_balance_for_collateral
                + sponsor_info.unused_storage_points()
        {
            *utx.storage_limit()
        } else {
            0
        };

        Ok((sponsored_gas, sponsored_collateral))
    }
}

#[cfg(test)]
mod tests {
    use crate::verification::PackingCheckResult;

    use super::TransactionPoolInner;
    use crate::keylib::{Generator, KeyPair, Random};
    use cfx_executor::{
        machine::{Machine, VmFactory},
        spec::CommonParams,
    };
    use cfx_parameters::block::{
        cspace_block_gas_limit_after_cip1559, espace_block_gas_limit,
    };
    use cfx_types::{Address, Space, SpaceMap, U256};
    use itertools::Itertools;
    use primitives::{
        block_header::compute_next_price_tuple,
        transaction::{
            native_transaction::NativeTransaction, Eip155Transaction,
        },
        Action, SignedTransaction, Transaction,
    };
    use std::sync::Arc;

    fn new_test_tx(
        sender: &KeyPair, nonce: usize, gas_price: usize, gas: usize,
        value: usize, space: Space,
    ) -> Arc<SignedTransaction> {
        let tx: Transaction = match space {
            Space::Native => NativeTransaction {
                nonce: U256::from(nonce),
                gas_price: U256::from(gas_price),
                gas: U256::from(gas),
                action: Action::Call(Address::random()),
                value: U256::from(value),
                storage_limit: 0,
                epoch_height: 0,
                chain_id: 1,
                data: Vec::new(),
            }
            .into(),
            Space::Ethereum => Eip155Transaction {
                nonce: U256::from(nonce),
                gas_price: U256::from(gas_price),
                gas: U256::from(gas),
                action: Action::Call(Address::random()),
                value: U256::from(value),
                chain_id: Some(1),
                data: Vec::new(),
            }
            .into(),
        };
        Arc::new(tx.sign(sender.secret()))
    }

    fn pack_transactions_1559_checked(
        pool: &mut TransactionPoolInner, machine: &Machine,
    ) {
        let parent_base_price = SpaceMap::new(100, 200).map_all(U256::from);
        let block_gas_limit = U256::from(6000);
        let best_epoch_height = 20;

        let (txs, base_price) = pool.pack_transactions_1559(
            usize::MAX,
            block_gas_limit,
            parent_base_price,
            usize::MAX,
            best_epoch_height,
            machine,
            |_| PackingCheckResult::Pack,
        );

        let params = machine.params();

        let core_gas_limit =
            cspace_block_gas_limit_after_cip1559(block_gas_limit);
        let eth_gas_limit = espace_block_gas_limit(
            params.can_pack_evm_transaction(best_epoch_height),
            block_gas_limit,
        );

        let gas_target =
            SpaceMap::new(core_gas_limit, eth_gas_limit).map_all(|x| x / 2);

        let mut gas_used = SpaceMap::default();
        let mut min_gas_price =
            SpaceMap::new(U256::max_value(), U256::max_value());

        for tx in txs {
            gas_used[tx.space()] += *tx.gas_limit();
            min_gas_price[tx.space()] =
                min_gas_price[tx.space()].min(*tx.gas_price());
        }

        let min_base_price = params.min_base_price();

        let expected_base_price = SpaceMap::zip4(
            gas_target,
            gas_used,
            parent_base_price,
            min_base_price,
        )
        .map_all(compute_next_price_tuple);

        assert_eq!(expected_base_price, base_price);
        assert!(gas_used[Space::Native] <= core_gas_limit);
        assert!(gas_used[Space::Ethereum] <= eth_gas_limit);

        for space in [Space::Native, Space::Ethereum] {
            assert!(base_price[space] <= min_gas_price[space]);
        }
    }

    #[test]
    fn test_pack_eip1559_transactions() {
        let mut pool = TransactionPoolInner::new_for_test();

        let mut params = CommonParams::default();
        params.min_base_price = SpaceMap::new(100, 200).map_all(U256::from);

        let machine = Arc::new(Machine::new(params, VmFactory::default()));

        let test_block_limit = SpaceMap::new(5400, 3000);

        let senders: Vec<_> = (0..20)
            .into_iter()
            .map(|_| Random.generate().unwrap())
            .collect();

        let tasks = [1, 2, 3]
            .into_iter()
            .cartesian_product(
                /* gas_price */ [50usize, 95, 100, 105, 150, 1000],
            )
            .cartesian_product(
                /* gas_limit_percent */ [5usize, 10, 40, 60, 100],
            )
            .cartesian_product(/* price_increasing */ [0usize, 1]);

        for (((space_bits, gas_price), gas_limit_percent), price_inc) in tasks {
            let tx_gas_limit =
                test_block_limit.map_all(|x| x * gas_limit_percent / 100);

            for (idx, sender) in senders.iter().enumerate() {
                let gas_price = gas_price + idx * price_inc;

                if space_bits & 0x1 != 0 {
                    let tx = new_test_tx(
                        sender,
                        0,
                        gas_price,
                        tx_gas_limit[Space::Native],
                        0,
                        Space::Native,
                    );
                    pool.insert_transaction_for_test(tx, U256::zero());
                }

                if space_bits & 0x2 != 0 {
                    let tx = new_test_tx(
                        sender,
                        0,
                        gas_price * 2,
                        tx_gas_limit[Space::Ethereum],
                        0,
                        Space::Ethereum,
                    );
                    pool.insert_transaction_for_test(tx, U256::zero());
                }
            }
            pack_transactions_1559_checked(&mut pool, &machine);
            pool.clear();
        }
    }
}
