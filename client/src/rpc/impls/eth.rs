// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    traits::eth::{Eth, EthFilter},
    types::{
        eth::{
            CallRequest, Filter, FilterChanges, Log, Receipt, RichBlock,
            SyncStatus, Transaction,
        },
        Bytes, EpochNumber as BlockNumber, Index,
    },
};
use cfx_types::{H160, H256, U256, U64};
use jsonrpc_core::BoxFuture;

pub struct EthHandler {
    // TODO
}

impl Eth for EthHandler {
    type Metadata = ();

    fn protocol_version(&self) -> jsonrpc_core::Result<String> { todo!() }

    fn syncing(&self) -> jsonrpc_core::Result<SyncStatus> { todo!() }

    fn hashrate(&self) -> jsonrpc_core::Result<U256> { todo!() }

    fn author(&self) -> jsonrpc_core::Result<H160> { todo!() }

    fn is_mining(&self) -> jsonrpc_core::Result<bool> { todo!() }

    fn chain_id(&self) -> jsonrpc_core::Result<Option<U64>> { todo!() }

    fn gas_price(&self) -> BoxFuture<U256> { todo!() }

    fn max_priority_fee_per_gas(&self) -> BoxFuture<U256> { todo!() }

    fn accounts(&self) -> jsonrpc_core::Result<Vec<H160>> { todo!() }

    fn block_number(&self) -> jsonrpc_core::Result<U256> { todo!() }

    fn balance(&self, _: H160, _: Option<BlockNumber>) -> BoxFuture<U256> {
        todo!()
    }

    fn storage_at(
        &self, _: H160, _: U256, _: Option<BlockNumber>,
    ) -> BoxFuture<H256> {
        todo!()
    }

    fn block_by_hash(&self, _: H256, _: bool) -> BoxFuture<Option<RichBlock>> {
        todo!()
    }

    fn block_by_number(
        &self, _: BlockNumber, _: bool,
    ) -> BoxFuture<Option<RichBlock>> {
        todo!()
    }

    fn transaction_count(
        &self, _: H160, _: Option<BlockNumber>,
    ) -> BoxFuture<U256> {
        todo!()
    }

    fn block_transaction_count_by_hash(
        &self, _: H256,
    ) -> BoxFuture<Option<U256>> {
        todo!()
    }

    fn block_transaction_count_by_number(
        &self, _: BlockNumber,
    ) -> BoxFuture<Option<U256>> {
        todo!()
    }

    fn block_uncles_count_by_hash(&self, _: H256) -> BoxFuture<Option<U256>> {
        todo!()
    }

    fn block_uncles_count_by_number(
        &self, _: BlockNumber,
    ) -> BoxFuture<Option<U256>> {
        todo!()
    }

    fn code_at(&self, _: H160, _: Option<BlockNumber>) -> BoxFuture<Bytes> {
        todo!()
    }

    fn send_raw_transaction(&self, _: Bytes) -> jsonrpc_core::Result<H256> {
        todo!()
    }

    fn submit_transaction(&self, _: Bytes) -> jsonrpc_core::Result<H256> {
        todo!()
    }

    fn call(&self, _: CallRequest, _: Option<BlockNumber>) -> BoxFuture<Bytes> {
        todo!()
    }

    fn estimate_gas(
        &self, _: CallRequest, _: Option<BlockNumber>,
    ) -> BoxFuture<U256> {
        todo!()
    }

    fn transaction_by_hash(&self, _: H256) -> BoxFuture<Option<Transaction>> {
        todo!()
    }

    fn transaction_by_block_hash_and_index(
        &self, _: H256, _: Index,
    ) -> BoxFuture<Option<Transaction>> {
        todo!()
    }

    fn transaction_by_block_number_and_index(
        &self, _: BlockNumber, _: Index,
    ) -> BoxFuture<Option<Transaction>> {
        todo!()
    }

    fn transaction_receipt(&self, _: H256) -> BoxFuture<Option<Receipt>> {
        todo!()
    }

    fn uncle_by_block_hash_and_index(
        &self, _: H256, _: Index,
    ) -> BoxFuture<Option<RichBlock>> {
        todo!()
    }

    fn uncle_by_block_number_and_index(
        &self, _: BlockNumber, _: Index,
    ) -> BoxFuture<Option<RichBlock>> {
        todo!()
    }

    fn compilers(&self) -> jsonrpc_core::Result<Vec<String>> { todo!() }

    fn compile_lll(&self, _: String) -> jsonrpc_core::Result<Bytes> { todo!() }

    fn compile_solidity(&self, _: String) -> jsonrpc_core::Result<Bytes> {
        todo!()
    }

    fn compile_serpent(&self, _: String) -> jsonrpc_core::Result<Bytes> {
        todo!()
    }

    fn logs(&self, _: Filter) -> BoxFuture<Vec<Log>> { todo!() }

    fn submit_hashrate(&self, _: U256, _: H256) -> jsonrpc_core::Result<bool> {
        todo!()
    }
}

impl EthFilter for EthHandler {
    fn new_filter(&self, _: Filter) -> jsonrpc_core::Result<U256> { todo!() }

    fn new_block_filter(&self) -> jsonrpc_core::Result<U256> { todo!() }

    fn new_pending_transaction_filter(&self) -> jsonrpc_core::Result<U256> {
        todo!()
    }

    fn filter_changes(&self, _: Index) -> BoxFuture<FilterChanges> { todo!() }

    fn filter_logs(&self, _: Index) -> BoxFuture<Vec<Log>> { todo!() }

    fn uninstall_filter(&self, _: Index) -> jsonrpc_core::Result<bool> {
        todo!()
    }
}
