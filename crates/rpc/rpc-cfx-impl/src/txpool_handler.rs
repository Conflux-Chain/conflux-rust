// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_addr::Network;
use cfx_parameters::staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT;
use cfx_rpc_cfx_api::TxPoolServer;
use cfx_rpc_cfx_types::{
    address::check_rpc_address_network, AccountPendingInfo,
    AccountPendingTransactions, RpcAddress, Transaction as RpcTransaction,
    TxPoolPendingNonceRange, TxPoolStatus, TxWithPoolInfo,
};
use cfx_rpc_utils::error::jsonrpsee_error_helpers::{
    internal_error_with_data, invalid_params_check,
};
use cfx_types::{Address, AddressSpaceUtil, H256, U256, U64};
use cfxcore::{
    errors::Error as CoreError, SharedConsensusGraph, SharedTransactionPool,
};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use primitives::transaction::Transaction;

pub struct TxPoolHandler {
    tx_pool: SharedTransactionPool,
    consensus: SharedConsensusGraph,
    network: Network,
}

impl TxPoolHandler {
    pub fn new(
        tx_pool: SharedTransactionPool, consensus: SharedConsensusGraph,
        network: Network,
    ) -> Self {
        Self {
            tx_pool,
            consensus,
            network,
        }
    }

    fn check_address_network(&self, address: &RpcAddress) -> RpcResult<()> {
        invalid_params_check(
            "address",
            check_rpc_address_network(Some(address.network), &self.network),
        )
    }
}

impl TxPoolServer for TxPoolHandler {
    fn txpool_status(&self) -> RpcResult<TxPoolStatus> {
        let (ready_len, deferred_len, received_len, unexecuted_len) =
            self.tx_pool.stats();
        Ok(TxPoolStatus {
            deferred: U64::from(deferred_len),
            ready: U64::from(ready_len),
            received: U64::from(received_len),
            unexecuted: U64::from(unexecuted_len),
        })
    }

    fn txpool_next_nonce(&self, address: RpcAddress) -> RpcResult<U256> {
        self.check_address_network(&address)?;
        Ok(self
            .tx_pool
            .get_next_nonce(&address.hex_address.with_native_space()))
    }

    fn txpool_transaction_by_address_and_nonce(
        &self, address: RpcAddress, nonce: U256,
    ) -> RpcResult<Option<RpcTransaction>> {
        self.check_address_network(&address)?;
        let tx = self
            .tx_pool
            .get_transaction_by_address2nonce(
                address.hex_address.with_native_space(),
                nonce,
            )
            .map(|tx| {
                RpcTransaction::from_signed(&tx, None, self.network)
                    .expect("success")
            });
        Ok(tx)
    }

    fn txpool_pending_nonce_range(
        &self, address: RpcAddress,
    ) -> RpcResult<TxPoolPendingNonceRange> {
        self.check_address_network(&address)?;

        let mut ret = TxPoolPendingNonceRange::default();
        let (pending_txs, _, _) = self
            .tx_pool
            .get_account_pending_transactions(
                &address.hex_address.with_native_space(),
                None,
                None,
                self.consensus.best_epoch_number(),
            )
            .map_err(|e| ErrorObjectOwned::from(CoreError::from(e)))?;

        let mut max_nonce: U256 = U256::from(0);
        let mut min_nonce: U256 = U256::max_value();
        for tx in pending_txs.iter() {
            if *tx.nonce() > max_nonce {
                max_nonce = *tx.nonce();
            }
            if *tx.nonce() < min_nonce {
                min_nonce = *tx.nonce();
            }
        }
        ret.min_nonce = min_nonce;
        ret.max_nonce = max_nonce;
        Ok(ret)
    }

    fn txpool_tx_with_pool_info(
        &self, hash: H256,
    ) -> RpcResult<TxWithPoolInfo> {
        let mut ret = TxWithPoolInfo::default();
        if let Some(tx) = self.tx_pool.get_transaction(&hash) {
            ret.exist = true;
            if self.tx_pool.check_tx_packed_in_deferred_pool(&hash) {
                ret.packed = true;
            }
            let (local_nonce, local_balance) =
                self.tx_pool.get_local_account_info(&tx.sender());
            let (state_nonce, state_balance) = self
                .tx_pool
                .get_state_account_info(&tx.sender())
                .map_err(|e| internal_error_with_data(format!("{}", e)))?;
            let required_storage_collateral =
                if let Transaction::Native(ref native_tx) = tx.unsigned {
                    U256::from(*native_tx.storage_limit())
                        * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
                } else {
                    U256::zero()
                };
            let required_balance = tx.value()
                + tx.gas() * tx.gas_price()
                + required_storage_collateral;
            ret.local_balance_enough = local_balance > required_balance;
            ret.state_balance_enough = state_balance > required_balance;
            ret.local_balance = local_balance;
            ret.local_nonce = local_nonce;
            ret.state_balance = state_balance;
            ret.state_nonce = state_nonce;
        }
        Ok(ret)
    }

    fn account_pending_info(
        &self, address: RpcAddress,
    ) -> RpcResult<Option<AccountPendingInfo>> {
        self.check_address_network(&address)?;

        match self.tx_pool.get_account_pending_info(
            &Address::from(address).with_native_space(),
        ) {
            None => Ok(None),
            Some((
                local_nonce,
                pending_count,
                pending_nonce,
                next_pending_tx,
            )) => Ok(Some(AccountPendingInfo {
                local_nonce: local_nonce.into(),
                pending_count: pending_count.into(),
                pending_nonce: pending_nonce.into(),
                next_pending_tx: next_pending_tx.into(),
            })),
        }
    }

    fn account_pending_transactions(
        &self, address: RpcAddress, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> RpcResult<AccountPendingTransactions> {
        self.check_address_network(&address)?;

        let (pending_txs, tx_status, pending_count) = self
            .tx_pool
            .get_account_pending_transactions(
                &Address::from(address).with_native_space(),
                maybe_start_nonce,
                maybe_limit.map(|limit| limit.as_usize()),
                self.consensus.best_epoch_number(),
            )
            .map_err(|e| ErrorObjectOwned::from(CoreError::from(e)))?;

        let pending_transactions = pending_txs
            .into_iter()
            .map(|tx| {
                RpcTransaction::from_signed(&tx, None, self.network)
                    .map_err(|e| ErrorObjectOwned::from(CoreError::from(e)))
            })
            .collect::<Result<Vec<RpcTransaction>, _>>()?;

        Ok(AccountPendingTransactions {
            pending_transactions,
            first_tx_status: tx_status,
            pending_count: pending_count.into(),
        })
    }
}
