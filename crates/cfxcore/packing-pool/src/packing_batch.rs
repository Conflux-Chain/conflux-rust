use cfx_types::U256;
use rand::RngCore;
use treap_map::{ApplyOpOutcome, Node};

use crate::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
    weight::PackingPoolWeight, PackingPoolConfig,
};
use malloc_size_of_derive::MallocSizeOf;

/// A batch of transactions that have the same sender and continuous nonces.
///
/// `PackingBatch` is designed to group transactions from the same sender that
/// can be packed into the same block. This struct ensures that all transactions
/// in the batch have the same sender and their nonces form a continuous
/// sequence.
#[derive(Default, Clone, Eq, PartialEq, Debug, MallocSizeOf)]
pub struct PackingBatch<TX: PackingPoolTransaction> {
    /// A list of transactions with the same sender and continuous nonces.
    /// This vector is guaranteed to contain at least one transaction. The
    /// transactions are sorted in the order of their nonces.
    pub(crate) txs: Vec<TX>,

    /// The total gas limit of all transactions in the batch.
    total_gas_limit: U256,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum InsertError {
    LargeNonce,
    TooLargeNonce,
    ExceedAddrTxCount,
    ExceedAddrGasLimit,
    DecreasingGasPrice,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum RemoveError {
    ShouldDelete,
}

#[derive(Debug)]
pub(crate) struct PackInfo {
    pub first_gas_price: U256,
    pub total_gas_limit: U256,
}

impl<TX: PackingPoolTransaction> PackingBatch<TX> {
    pub fn new(tx: TX) -> Self {
        let total_gas_limit = tx.gas_limit();
        Self {
            txs: vec![tx],
            total_gas_limit,
        }
    }

    #[inline]
    pub fn sender(&self) -> TX::Sender { self.txs.first().unwrap().sender() }

    #[inline]
    pub fn start_nonce(&self) -> U256 { self.txs.first().unwrap().nonce() }

    #[inline]
    pub fn first_gas_price(&self) -> U256 {
        self.txs.first().unwrap().gas_price()
    }

    #[inline]
    pub fn total_gas_limit(&self) -> U256 { self.total_gas_limit }

    #[inline]
    pub(crate) fn pack_info(&self) -> PackInfo {
        PackInfo {
            first_gas_price: self.first_gas_price(),
            total_gas_limit: self.total_gas_limit(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize { self.txs.len() }

    #[inline]
    /// Inserts a transaction into the pool according to [`PackingPoolConfig`],
    /// without violating the assumptions of [`PackingBatch`].
    ///
    /// # Returns
    /// Returns a tuple consisting of:
    /// - A vector of transactions that were replaced by the insertion. This can
    ///   be empty if no transactions were displaced.
    /// - A result indicating the success or failure of the insertion operation.
    pub fn insert(
        &mut self, mut tx: TX, config: &PackingPoolConfig,
    ) -> (Vec<TX>, Result<(), InsertError>) {
        use self::InsertError::*;
        assert_eq!(tx.sender(), self.sender());

        if tx.nonce() >= U256::MAX - 1 {
            return (vec![], Err(TooLargeNonce));
        }

        let start_nonce = self.start_nonce();
        let n_txs = self.len();

        let txs = &mut self.txs;
        if tx.nonce() + 1 < start_nonce
            || (tx.nonce() + 1 == start_nonce
                && tx.gas_price() > txs[0].gas_price())
        {
            let old_txs = std::mem::take(txs);
            *self = Self::new(tx);
            return (old_txs, Ok(()));
        }

        if tx.nonce() + 1 == start_nonce && tx.gas_price() <= txs[0].gas_price()
        {
            txs.insert(0, tx);
            let (truncate_idx, addr_gas_limit) =
                config.check_acceptable_batch(&*txs, None);
            let ret = self.txs.split_off(truncate_idx);
            self.total_gas_limit = addr_gas_limit;
            return (ret, Ok(()));
        }

        if tx.nonce() > start_nonce + n_txs {
            return (vec![], Err(LargeNonce));
        }

        if tx.nonce() == start_nonce + n_txs {
            // Append tx
            if n_txs >= config.address_tx_count {
                return (vec![], Err(ExceedAddrTxCount));
            }

            if txs.last().unwrap().gas_price() > tx.gas_price() {
                return (vec![], Err(DecreasingGasPrice));
            }
            if config.address_gas_limit
                < self.total_gas_limit.saturating_add(tx.gas_limit())
            {
                return (vec![], Err(ExceedAddrGasLimit));
            }

            self.total_gas_limit += tx.gas_limit();
            txs.push(tx);

            (vec![], Ok(()))
        } else {
            // Replace
            let to_replaced_idx = (tx.nonce() - start_nonce).as_usize();
            if to_replaced_idx > 0
                && tx.gas_price() < txs[to_replaced_idx - 1].gas_price()
            {
                let old_txs = self.txs.split_off(to_replaced_idx);
                self.update_total_limit();
                return (old_txs, Err(DecreasingGasPrice));
            }

            let (truncate_idx, addr_gas_limit) = config
                .check_acceptable_batch(&*txs, Some((&tx, to_replaced_idx)));
            if truncate_idx <= to_replaced_idx {
                let old_txs = self.txs.split_off(to_replaced_idx);
                self.update_total_limit();
                return (old_txs, Err(ExceedAddrGasLimit));
            }
            let my_gas_price = tx.gas_price();

            std::mem::swap(&mut txs[to_replaced_idx], &mut tx);

            let mut res = vec![tx];
            let truncated_txs;
            if txs
                .get(to_replaced_idx + 1)
                .map_or(false, |tx| tx.gas_price() < my_gas_price)
            {
                truncated_txs = txs.split_off(to_replaced_idx + 1);
                self.update_total_limit();
            } else {
                truncated_txs = txs.split_off(truncate_idx);
                self.total_gas_limit = addr_gas_limit;
            };
            res.extend(truncated_txs);

            (res, Ok(()))
        }
    }

    /// Removes transactions starting from the specified index (included) and
    /// returns them.
    pub fn split_off_suffix(
        &mut self, index: usize,
    ) -> Result<Vec<TX>, RemoveError> {
        self.split_off_inner(index, true)
    }

    /// Removes transactions ending at the specified index (not included) and
    /// returns them.
    pub fn split_off_prefix(
        &mut self, index: usize,
    ) -> Result<Vec<TX>, RemoveError> {
        self.split_off_inner(index, false)
    }

    fn split_off_inner(
        &mut self, index: usize, keep_prefix: bool,
    ) -> Result<Vec<TX>, RemoveError> {
        if index == 0 || index >= self.len() {
            return if (index == 0) ^ keep_prefix {
                Ok(vec![])
            } else {
                Err(RemoveError::ShouldDelete)
            };
        }

        let mut res = self.txs.split_off(index);
        if !keep_prefix {
            std::mem::swap(&mut res, &mut self.txs);
        }

        self.update_total_limit();
        Ok(res)
    }

    fn update_total_limit(&mut self) {
        self.total_gas_limit = self
            .txs
            .iter()
            .map(|x| x.gas_limit())
            .fold(U256::zero(), |acc, e| acc + e);
    }

    /// Split transactions at the specified nonce (the specified one is in the
    /// past half). Retains a half according to `keep_prefix` and returns the
    /// rest half.
    pub fn split_off_by_nonce(
        &mut self, nonce: &U256, keep_prefix: bool,
    ) -> Result<Vec<TX>, RemoveError> {
        if *nonce < self.start_nonce() {
            self.split_off_inner(0, keep_prefix)
        } else if *nonce >= self.start_nonce() + self.len() {
            self.split_off_inner(self.len(), keep_prefix)
        } else {
            self.split_off_inner(
                (nonce - self.start_nonce()).as_usize(),
                keep_prefix,
            )
        }
    }

    #[inline]
    pub(crate) fn make_outcome_on_delete(&mut self) -> ApplyOpOutcome<Vec<TX>> {
        let txs = std::mem::take(&mut self.txs);
        ApplyOpOutcome {
            out: txs,
            update_weight: false,
            update_key: false,
            delete_item: true,
        }
    }

    pub(crate) fn make_node(
        self, config: &PackingPoolConfig, rng: &mut dyn RngCore,
    ) -> treap_map::Node<PackingPoolMap<TX>> {
        let key = self.txs.first().unwrap().sender();
        let gas_price = self.first_gas_price();
        let sort_key = gas_price;
        let loss_ratio = config.loss_ratio(sort_key);
        let weight = PackingPoolWeight {
            gas_limit: self.total_gas_limit,
            min_gas_price: gas_price,
            weighted_loss_ratio: loss_ratio * self.total_gas_limit,
            max_loss_ratio: loss_ratio,
        };
        Node::new(key, self, sort_key, weight, rng.next_u64())
    }

    #[cfg(test)]
    pub fn assert_constraints(&self) {
        assert!(self.txs.len() > 0);
        for i in 0..(self.txs.len() - 1) {
            assert_eq!(self.txs[i].sender(), self.txs[i + 1].sender());
            assert_eq!(self.txs[i].nonce() + 1, self.txs[i + 1].nonce());
            assert!(self.txs[i].gas_price() <= self.txs[i + 1].gas_price());
        }
        assert_eq!(
            self.total_gas_limit.as_u128(),
            self.txs.iter().map(|x| x.gas_limit().as_u128()).sum()
        );
    }

    #[cfg(test)]
    fn insert_test(
        &mut self, tx: TX, config: &PackingPoolConfig,
        expected_output: Vec<TX>, expected_status: Result<(), InsertError>,
    ) where
        TX: Copy + Ord + std::fmt::Debug,
    {
        let mut before_txs = self.txs.clone();
        before_txs.push(tx);

        let (res_txs, res) = self.insert(tx, &config);

        let mut after_txs = res_txs.clone();
        if res.is_err() {
            after_txs.push(tx);
        }
        after_txs.extend(&self.txs);

        before_txs.sort();
        after_txs.sort();
        assert_eq!(before_txs, after_txs);
        self.assert_constraints();
        assert_eq!(expected_output, res_txs);
        assert_eq!(expected_status, res);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::InsertError::*;
    use crate::{mock_tx::MockTransaction, PackingBatch, PackingPoolConfig};

    fn default_batch(len: usize) -> PackingBatch<MockTransaction> {
        let config = PackingPoolConfig::new_for_test();
        let mut batch = PackingBatch::new(default_tx(2));
        for i in 3..(len as u64 + 2) {
            batch.insert(default_tx(i), &config).1.unwrap();
        }
        batch.assert_constraints();
        batch
    }

    fn default_tx(i: u64) -> MockTransaction {
        static ID: AtomicUsize = AtomicUsize::new(0);
        MockTransaction {
            sender: 0,
            nonce: i,
            gas_price: i,
            gas_limit: i,
            id: ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        }
    }

    fn default_split_task() -> (
        PackingBatch<MockTransaction>,
        Vec<MockTransaction>,
        Vec<MockTransaction>,
        Vec<MockTransaction>,
    ) {
        let batch = default_batch(5);
        let (prefix, suffix) = batch.txs.split_at(3);
        let (prefix, suffix) = (prefix.to_vec(), suffix.to_vec());
        let all = batch.txs.clone();
        (batch, all, prefix, suffix)
    }

    #[test]
    fn test_insert_basic() {
        let mut batch = default_batch(5);
        let config = &PackingPoolConfig::new_for_test();

        // Append
        batch.insert_test(default_tx(7), config, vec![], Ok(()));

        // Append with large nonce
        batch.insert_test(default_tx(9), config, vec![], Err(LargeNonce));

        // Append with small nonce
        batch.insert_test(default_tx(1), config, vec![], Ok(()));

        // Append with small price
        let mut tx = default_tx(8);
        tx.gas_price = 6;
        batch.insert_test(tx, config, vec![], Err(DecreasingGasPrice));

        // Replace
        let tx = default_tx(4);
        let old_tx = batch.txs[3];
        batch.insert_test(tx, config, vec![old_tx], Ok(()));

        // Replace smaller (acceptable) price
        let mut tx = default_tx(4);
        tx.gas_price = 3;
        let old_tx = batch.txs[3];
        batch.insert_test(tx, &config, vec![old_tx], Ok(()));

        // Replace larger (acceptable) gas
        let mut tx = default_tx(4);
        tx.gas_price = 5;
        let old_tx = batch.txs[3];
        batch.insert_test(tx, &config, vec![old_tx], Ok(()));

        // Replace large price
        let mut tx = default_tx(4);
        tx.gas_price = 6;
        let old_txs = batch.txs[3..].to_vec();
        batch.insert_test(tx, &config, old_txs, Ok(()));

        // Replace small price
        let mut tx = default_tx(3);
        tx.gas_price = 1;
        let old_txs = batch.txs[2..].to_vec();
        batch.insert_test(tx, &config, old_txs, Err(DecreasingGasPrice));

        // Insert in-continous nonce
        let mut batch = default_batch(5);
        let old_txs = batch.txs.clone();
        batch.insert_test(default_tx(0), &config, old_txs, Ok(()));

        // Insert large price in front
        let mut batch = default_batch(5);
        let mut tx = default_tx(1);
        tx.gas_price = 10;
        let old_txs = batch.txs.clone();
        batch.insert_test(tx, &config, old_txs, Ok(()));

        // Replace large gas limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(4);
        tx.gas_limit = config.address_gas_limit.as_u64();
        let old_txs = batch.txs[2..].to_vec();
        batch.insert_test(tx, &config, old_txs, Err(ExceedAddrGasLimit));

        // Replace acceptable but truncate gas limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(4);
        tx.gas_limit = config.address_gas_limit.as_u64() - 10;
        let old_txs = vec![batch.txs[2], batch.txs[4]];
        batch.insert_test(tx, &config, old_txs, Ok(()));
    }

    #[test]
    fn test_large_gas_limit() {
        let config = &PackingPoolConfig::new_for_test();

        // Append with large limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(7);
        tx.gas_limit = config.address_gas_limit.as_u64() - 2;
        batch.insert_test(tx, config, vec![], Err(ExceedAddrGasLimit));

        // Replace with large gas limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(4);
        tx.gas_limit = config.address_gas_limit.as_u64();
        let old_txs = batch.txs[2..].to_vec();
        batch.insert_test(tx, &config, old_txs, Err(ExceedAddrGasLimit));

        // Replace acceptable but truncate gas limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(4);
        tx.gas_limit = config.address_gas_limit.as_u64() - 10;
        let old_txs = vec![batch.txs[2], batch.txs[4]];
        batch.insert_test(tx, &config, old_txs, Ok(()));

        // Replace first with large gas limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(1);
        tx.gas_limit = config.address_gas_limit.as_u64() - 1;
        let old_txs = batch.txs.clone();
        batch.insert_test(tx, &config, old_txs, Ok(()));

        // Replace first with large gas limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(1);
        tx.gas_limit = config.address_gas_limit.as_u64() + 1;
        let old_txs = batch.txs.clone();
        batch.insert_test(tx, &config, old_txs, Ok(()));

        // Insert front with large gas limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(0);
        tx.gas_limit = config.address_gas_limit.as_u64() - 1;
        let old_txs = batch.txs.clone();
        batch.insert_test(tx, &config, old_txs, Ok(()));

        // Insert front with large gas limit
        let mut batch = default_batch(5);
        let mut tx = default_tx(0);
        tx.gas_limit = config.address_gas_limit.as_u64() + 1;
        let old_txs = batch.txs.clone();
        batch.insert_test(tx, &config, old_txs, Ok(()));
    }

    #[test]
    fn test_many_transactions() {
        let config = &PackingPoolConfig::new_for_test();

        // Append
        let mut batch = default_batch(20);
        batch.insert_test(
            default_tx(22),
            config,
            vec![],
            Err(ExceedAddrTxCount),
        );

        // Replace
        let old_tx = batch.txs[19];
        batch.insert_test(default_tx(21), config, vec![old_tx], Ok(()));

        // Insert front
        let old_tx = batch.txs[19];
        batch.insert_test(default_tx(1), config, vec![old_tx], Ok(()));

        // Insert skipped front
        let mut batch = default_batch(20);
        let old_txs = batch.txs.clone();
        batch.insert_test(default_tx(0), config, old_txs, Ok(()));
    }

    #[test]
    #[allow(unused_variables)]
    fn test_split_off() {
        use super::RemoveError::ShouldDelete;
        let config = &PackingPoolConfig::new_for_test();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_prefix(3), Ok(prefix));
        assert_eq!(batch.txs, suffix);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_suffix(3), Ok(suffix));
        assert_eq!(batch.txs, prefix);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_prefix(0), Ok(vec![]));
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_suffix(0), Err(ShouldDelete));
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_prefix(5), Err(ShouldDelete));
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_suffix(5), Ok(vec![]));
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_by_nonce(&5.into(), false), Ok(prefix));
        assert_eq!(batch.txs, suffix);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_by_nonce(&5.into(), true), Ok(suffix));
        assert_eq!(batch.txs, prefix);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_by_nonce(&2.into(), false), Ok(vec![]));
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(
            batch.split_off_by_nonce(&2.into(), true),
            Err(ShouldDelete)
        );
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_by_nonce(&1.into(), false), Ok(vec![]));
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(
            batch.split_off_by_nonce(&1.into(), true),
            Err(ShouldDelete)
        );
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(
            batch.split_off_by_nonce(&7.into(), false),
            Err(ShouldDelete)
        );
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_by_nonce(&7.into(), true), Ok(vec![]));
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(
            batch.split_off_by_nonce(&8.into(), false),
            Err(ShouldDelete)
        );
        assert_eq!(batch.txs, all);
        batch.assert_constraints();

        let (mut batch, all, prefix, suffix) = default_split_task();
        assert_eq!(batch.split_off_by_nonce(&8.into(), true), Ok(vec![]));
        assert_eq!(batch.txs, all);
        batch.assert_constraints();
    }
}
