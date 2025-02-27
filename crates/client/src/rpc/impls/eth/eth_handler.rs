// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    errors::{internal_error, EthApiError},
    impls::RpcImplConfiguration,
    traits::eth_space::eth::Eth,
    types::{
        eth::{
            AccountPendingTransactions, Block as RpcBlock, BlockNumber,
            BlockOverrides, EthRpcLogFilter, Log, Receipt, RpcStateOverride,
            SyncStatus, Transaction, TransactionRequest,
        },
        Bytes, FeeHistory, Index, U64 as HexU64,
    },
};
use cfx_rpc::EthApi;
use cfx_tasks::TaskExecutor;
use cfx_types::{Address, AddressSpaceUtil, Space, H160, H256, U256, U64};
use cfx_util_macros::bail;
use cfxcore::{
    SharedConsensusGraph, SharedSynchronizationService, SharedTransactionPool,
};
use jsonrpc_core::Result as RpcResult;
use log::debug;
use primitives::TransactionWithSignature;

pub struct EthHandler {
    inner: EthApi,
}

impl EthHandler {
    pub fn new(
        config: RpcImplConfiguration, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
        executor: TaskExecutor,
    ) -> Self {
        EthHandler {
            inner: EthApi::new(config, consensus, sync, tx_pool, executor),
        }
    }
}

impl Eth for EthHandler {
    fn client_version(&self) -> RpcResult<String> {
        debug!("RPC Request: web3_clientVersion()");
        Ok(parity_version::conflux_client_version!())
    }

    fn net_version(&self) -> RpcResult<String> {
        debug!("RPC Request: net_version()");
        Ok(format!("{}", self.inner.chain_id()))
    }

    fn protocol_version(&self) -> RpcResult<String> {
        debug!("RPC Request: eth_protocolVersion()");
        // 65 is a common ETH version now
        Ok(format!("{}", 65))
    }

    fn syncing(&self) -> RpcResult<SyncStatus> {
        debug!("RPC Request: eth_syncing()");
        Ok(self.inner.sync_status())
    }

    fn hashrate(&self) -> RpcResult<U256> {
        debug!("RPC Request: eth_hashrate()");
        // We do not mine
        Ok(U256::zero())
    }

    fn author(&self) -> RpcResult<H160> {
        debug!("RPC Request: eth_coinbase()");
        // We do not care this, just return zero address
        Ok(H160::zero())
    }

    fn is_mining(&self) -> RpcResult<bool> {
        debug!("RPC Request: eth_mining()");
        // We do not mine from ETH perspective
        Ok(false)
    }

    fn chain_id(&self) -> RpcResult<Option<U64>> {
        debug!("RPC Request: eth_chainId()");
        return Ok(Some(self.inner.chain_id().into()));
    }

    fn gas_price(&self) -> RpcResult<U256> {
        debug!("RPC Request: eth_gasPrice()");
        Ok(self.inner.gas_price())
    }

    fn max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        debug!("RPC Request: eth_maxPriorityFeePerGas()");
        self.inner
            .max_priority_fee_per_gas()
            .map_err(|err| err.into())
    }

    fn accounts(&self) -> RpcResult<Vec<H160>> {
        debug!("RPC Request: eth_accounts()");
        // Conflux eSpace does not manage accounts
        Ok(vec![])
    }

    fn block_number(&self) -> RpcResult<U256> {
        debug!("RPC Request: eth_blockNumber()");
        self.inner.latest_block_number().map_err(|err| err.into())
    }

    fn balance(
        &self, address: H160, num: Option<BlockNumber>,
    ) -> RpcResult<U256> {
        debug!(
            "RPC Request: eth_getBalance(address={:?}, epoch_num={:?})",
            address, num
        );

        self.inner
            .user_balance(address, num)
            .map_err(|err| err.into())
    }

    fn storage_at(
        &self, address: H160, position: U256, block_num: Option<BlockNumber>,
    ) -> RpcResult<H256> {
        debug!(
            "RPC Request: eth_getStorageAt(address={:?}, position={:?}, block_num={:?})",
            address, position, block_num
        );

        self.inner
            .storage_at(address, position, block_num)
            .map_err(|err| err.into())
    }

    fn block_by_hash(
        &self, hash: H256, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        debug!(
            "RPC Request: eth_getBlockByHash(hash={:?}, include_txs={:?})",
            hash, include_txs
        );

        self.inner
            .block_by_hash(hash, include_txs)
            .map_err(|err| err.into())
    }

    fn block_by_number(
        &self, block_num: BlockNumber, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        debug!("RPC Request: eth_getBlockByNumber(block_number={:?}, include_txs={:?})", block_num, include_txs);

        self.inner
            .block_by_number(block_num, include_txs)
            .map_err(|err| err.into())
    }

    fn transaction_count(
        &self, address: H160, num: Option<BlockNumber>,
    ) -> RpcResult<U256> {
        debug!(
            "RPC Request: eth_getTransactionCount(address={:?}, block_number={:?})",
            address, num
        );

        self.inner
            .next_nonce(address, num)
            .map_err(|err| err.into())
    }

    fn block_transaction_count_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<U256>> {
        debug!(
            "RPC Request: eth_getBlockTransactionCountByHash(hash={:?})",
            hash,
        );

        self.inner
            .block_transaction_count_by_hash(hash)
            .map_err(|err| err.into())
    }

    fn block_transaction_count_by_number(
        &self, block_num: BlockNumber,
    ) -> RpcResult<Option<U256>> {
        debug!(
            "RPC Request: eth_getBlockTransactionCountByNumber(block_number={:?})",
            block_num
        );

        self.inner
            .block_transaction_count_by_number(block_num)
            .map_err(|err| err.into())
    }

    fn block_uncles_count_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<U256>> {
        debug!("RPC Request: eth_getUncleCountByBlockHash(hash={:?})", hash);

        self.inner
            .block_uncles_count_by_hash(hash)
            .map_err(|err| err.into())
    }

    fn block_uncles_count_by_number(
        &self, block_num: BlockNumber,
    ) -> RpcResult<Option<U256>> {
        debug!(
            "RPC Request: eth_getUncleCountByBlockNumber(block_number={:?})",
            block_num
        );

        self.inner
            .block_uncles_count_by_number(block_num)
            .map_err(|err| err.into())
    }

    fn code_at(
        &self, address: H160, epoch_num: Option<BlockNumber>,
    ) -> RpcResult<Bytes> {
        debug!(
            "RPC Request: eth_getCode(address={:?}, epoch_num={:?})",
            address, epoch_num
        );

        self.inner
            .code_at(address, epoch_num)
            .map_err(|err| err.into())
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        debug!("RPC Request: eth_sendRawTransaction(raw={:?})", raw,);
        let tx = if let Ok(tx) =
            TransactionWithSignature::from_raw(&raw.into_vec())
        {
            tx
        } else {
            bail!(EthApiError::FailedToDecodeSignedTransaction)
        };

        if tx.space() != Space::Ethereum {
            bail!(EthApiError::Other(
                "Incorrect transaction space".to_string()
            ));
        }

        if tx.recover_public().is_err() {
            bail!(EthApiError::InvalidTransactionSignature);
        }

        let r = self.inner.send_transaction_with_signature(tx)?;
        Ok(r)
    }

    fn submit_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        self.send_raw_transaction(raw)
    }

    fn call(
        &self, request: TransactionRequest,
        block_number_or_hash: Option<BlockNumber>,
        state_overrides: Option<RpcStateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<Bytes> {
        debug!(
            "RPC Request: eth_call(request={:?}, block_num={:?})",
            request, block_number_or_hash
        );
        let (execution, _estimation) = self.inner.exec_transaction(
            request,
            block_number_or_hash,
            state_overrides,
            block_overrides,
        )?;

        Ok(execution.output.into())
    }

    fn estimate_gas(
        &self, request: TransactionRequest,
        block_number_or_hash: Option<BlockNumber>,
        state_overrides: Option<RpcStateOverride>,
    ) -> RpcResult<U256> {
        debug!(
            "RPC Request: eth_estimateGas(request={:?}, block_num={:?})",
            request, block_number_or_hash
        );
        let (_, estimated_gas) = self.inner.exec_transaction(
            request,
            block_number_or_hash,
            state_overrides,
            None,
        )?;

        Ok(estimated_gas)
    }

    fn fee_history(
        &self, block_count: HexU64, newest_block: BlockNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory> {
        debug!(
            "RPC Request: eth_feeHistory(block_count={}, newest_block={:?}, reward_percentiles={:?})",
            block_count, newest_block, reward_percentiles
        );

        self.inner
            .fee_history(block_count, newest_block, reward_percentiles)
            .map_err(|err| err.into())
    }

    fn transaction_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<Transaction>> {
        debug!("RPC Request: eth_getTransactionByHash(hash={:?})", hash);

        self.inner
            .transaction_by_hash(hash)
            .map_err(|err| err.into())
    }

    fn transaction_by_block_hash_and_index(
        &self, hash: H256, idx: Index,
    ) -> RpcResult<Option<Transaction>> {
        debug!("RPC Request: eth_getTransactionByBlockHashAndIndex(hash={:?}, idx={:?})", hash, idx);

        let phantom_block = self.inner.phantom_block_by_hash(hash)?;

        Ok(EthApi::block_tx_by_index(phantom_block, idx.value()))
    }

    fn transaction_by_block_number_and_index(
        &self, block_num: BlockNumber, idx: Index,
    ) -> RpcResult<Option<Transaction>> {
        debug!("RPC Request: eth_getTransactionByBlockNumberAndIndex(block_num={:?}, idx={:?})", block_num, idx);

        let phantom_block = self.inner.phantom_block_by_number(block_num)?;

        Ok(EthApi::block_tx_by_index(phantom_block, idx.value()))
    }

    fn transaction_receipt(&self, tx_hash: H256) -> RpcResult<Option<Receipt>> {
        debug!(
            "RPC Request: eth_getTransactionReceipt(tx_hash={:?})",
            tx_hash
        );

        self.inner
            .transaction_receipt(tx_hash)
            .map_err(|err| err.into())
    }

    fn uncle_by_block_hash_and_index(
        &self, hash: H256, idx: Index,
    ) -> RpcResult<Option<RpcBlock>> {
        debug!(
            "RPC Request: eth_getUncleByBlockHashAndIndex(hash={:?}, idx={:?})",
            hash, idx
        );
        // We do not have uncle block
        Ok(None)
    }

    fn uncle_by_block_number_and_index(
        &self, block_num: BlockNumber, idx: Index,
    ) -> RpcResult<Option<RpcBlock>> {
        debug!("RPC Request: eth_getUncleByBlockNumberAndIndex(block_num={:?}, idx={:?})", block_num, idx);
        // We do not have uncle block
        Ok(None)
    }

    fn logs(&self, filter: EthRpcLogFilter) -> RpcResult<Vec<Log>> {
        debug!("RPC Request: eth_getLogs(filter={:?})", filter);

        self.inner.logs(filter).map_err(|err| err.into())
    }

    fn submit_hashrate(&self, _: U256, _: H256) -> RpcResult<bool> {
        debug!("RPC Request: eth_submitHashrate()");
        // We do not care mining
        Ok(false)
    }

    fn eth_block_receipts(
        &self, block: BlockNumber,
    ) -> RpcResult<Vec<Receipt>> {
        debug!(
            "RPC Request: eth_getBlockReceipts(block_number={:?})",
            block
        );

        self.inner.get_block_receipts(block).map_err(|e| e.into())
    }

    fn block_receipts(
        &self, block_num: Option<BlockNumber>,
    ) -> RpcResult<Vec<Receipt>> {
        debug!(
            "RPC Request: parity_getBlockReceipts(block_number={:?})",
            block_num
        );

        let block_num = block_num.unwrap_or_default();
        self.inner
            .get_block_receipts(block_num)
            .map_err(|e| e.into())
    }

    fn account_pending_transactions(
        &self, address: H160, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> RpcResult<AccountPendingTransactions> {
        debug!("RPC Request: eth_getAccountPendingTransactions(addr={:?}, start_nonce={:?}, limit={:?})",
              address, maybe_start_nonce, maybe_limit);

        let (pending_txs, tx_status, pending_count) = self
            .inner
            .tx_pool()
            .get_account_pending_transactions(
                &Address::from(address).with_evm_space(),
                maybe_start_nonce,
                maybe_limit.map(|limit| limit.as_usize()),
                self.inner.best_epoch_number(),
            )
            .map_err(|e| internal_error(e))?;
        Ok(AccountPendingTransactions {
            pending_transactions: pending_txs
                .into_iter()
                .map(|tx| {
                    Transaction::from_signed(
                        &tx,
                        (None, None, None),
                        (None, None),
                    )
                })
                .collect(),
            first_tx_status: tx_status,
            pending_count: pending_count.into(),
        })
    }
}
