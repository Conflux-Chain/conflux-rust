use cfx_types::U256;
use rand::RngCore;
use treap_map::{ApplyOpOutcome, Node};

use crate::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
    weight::PackingPoolWeight, PackingPoolConfig,
};
use malloc_size_of_derive::MallocSizeOf;

#[derive(Default, Clone, Eq, PartialEq, MallocSizeOf)]
pub struct PackingBatch<TX: PackingPoolTransaction> {
    pub(crate) txs: Vec<TX>,
    total_gas_limit: U256,
}

pub enum InsertError {
    Append(AppendError),
    Replace(ReplaceError, usize),
}

pub enum AppendError {
    SmallNonce,
    LargeNonce,
    TooLargeNonce,
    ExceedAddrTxCount,
    ExceedAddrGasLimit,
    DecreasingGasPrice,
}

pub enum ReplaceError {
    ExceedAddrGasLimit,
    DecreasingGasPrice,
    NotEnoughReplaceGasPrice,
}

pub enum RemoveError {
    ShouldDelete,
}

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
    pub fn insert(
        &mut self, mut tx: TX, config: &PackingPoolConfig,
    ) -> Result<Vec<TX>, InsertError> {
        use self::{AppendError::*, InsertError::*, ReplaceError::*};
        assert_eq!(tx.sender(), self.sender());

        if tx.nonce() >= U256::MAX - 1 {
            return Err(Append(TooLargeNonce));
        }

        let start_nonce = self.start_nonce();
        let n_txs = self.len();

        let txs = &mut self.txs;
        if tx.nonce() < start_nonce {
            return Err(Append(SmallNonce));
        }

        if tx.nonce() > start_nonce + n_txs {
            return Err(Append(LargeNonce));
        }

        if tx.nonce() == start_nonce + n_txs {
            // Insert tx
            if n_txs >= config.address_tx_count {
                return Err(Append(AppendError::ExceedAddrTxCount));
            }

            if txs.last().unwrap().gas_price() > tx.gas_price() {
                return Err(Append(AppendError::DecreasingGasPrice));
            }
            if config.address_gas_limit
                < self.total_gas_limit.saturating_add(tx.gas_limit())
            {
                return Err(Append(AppendError::ExceedAddrGasLimit));
            }

            self.total_gas_limit += tx.gas_limit();
            txs.push(tx);

            Ok(vec![])
        } else {
            // Replace
            let to_replaced_idx = (tx.nonce() - start_nonce).as_usize();
            let to_replaced_tx = &txs[to_replaced_idx];
            if tx.gas_price()
                < config.next_gas_price(to_replaced_tx.gas_price())
            {
                return Err(Replace(NotEnoughReplaceGasPrice, to_replaced_idx));
            }
            if to_replaced_idx > 0
                && tx.gas_price() < txs[to_replaced_idx - 1].gas_price()
            {
                return Err(Replace(
                    ReplaceError::DecreasingGasPrice,
                    to_replaced_idx,
                ));
            }

            let (truncate_idx, addr_gas_limit) = config
                .check_address_gas_limit(
                    &*txs,
                    to_replaced_tx,
                    to_replaced_idx,
                );
            if truncate_idx <= to_replaced_idx {
                return Err(Replace(
                    ReplaceError::ExceedAddrGasLimit,
                    to_replaced_idx,
                ));
            }

            std::mem::swap(&mut txs[to_replaced_idx], &mut tx);

            let mut res = vec![tx];
            res.extend(txs.split_off(truncate_idx));

            self.total_gas_limit = addr_gas_limit;

            Ok(res)
        }
    }

    pub fn split_off_suffix(
        &mut self, index: usize,
    ) -> Result<Vec<TX>, RemoveError> {
        self.split_off_inner(index, true)
    }

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
        if keep_prefix {
            std::mem::swap(&mut res, &mut self.txs);
        }

        self.total_gas_limit = self
            .txs
            .iter()
            .map(|x| x.gas_limit())
            .fold(U256::zero(), |acc, e| acc + e);
        Ok(res)
    }

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
            weighted_loss_ratio: loss_ratio * self.total_gas_limit,
            max_loss_ratio: loss_ratio,
        };
        Node::new(key, self, sort_key, weight, rng.next_u64())
    }
}
