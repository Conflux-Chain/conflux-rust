// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    pos::PoSEpochReward, Account as RpcAccount, AccountPendingInfo,
    AccountPendingTransactions, Block, BlockHashOrEpochNumber, Bytes,
    CfxFeeHistory, CfxRpcLogFilter, CheckBalanceAgainstTransactionResponse,
    EpochNumber, EstimateGasAndCollateralResponse, Log as RpcLog, PoSEconomics,
    Receipt as RpcReceipt, RewardInfo as RpcRewardInfo, RpcAddress,
    SponsorInfo, Status as RpcStatus, StorageCollateralInfo, TokenSupplyInfo,
    Transaction, TransactionRequest, VoteParamsInfo, U64 as HexU64,
};
use cfx_types::{H256, U256, U64};
use jsonrpc_core::{BoxFuture, Result as JsonRpcResult};
use jsonrpc_derive::rpc;
use primitives::{DepositInfo, StorageRoot, VoteStakeInfo};

/// Cfx rpc interface.
#[rpc(server)]
pub trait Cfx {
    //        /// Returns protocol version encoded as a string (quotes are
    // necessary).        #[rpc(name = "cfx_protocolVersion")]
    //        fn protocol_version(&self) -> JsonRpcResult<String>;
    //
    /// Returns the number of hashes per second that the node is mining with.
    //        #[rpc(name = "cfx_hashrate")]
    //        fn hashrate(&self) -> JsonRpcResult<U256>;

    //        /// Returns block author.
    //        #[rpc(name = "cfx_coinbase")]
    //        fn author(&self) -> JsonRpcResult<H160>;

    //        /// Returns true if client is actively mining new blocks.
    //        #[rpc(name = "cfx_mining")]
    //        fn is_mining(&self) -> JsonRpcResult<bool>;

    /// Returns current gas price.
    #[rpc(name = "cfx_gasPrice")]
    fn gas_price(&self) -> BoxFuture<JsonRpcResult<U256>>;

    /// Returns current max_priority_fee
    #[rpc(name = "cfx_maxPriorityFeePerGas")]
    fn max_priority_fee_per_gas(&self) -> BoxFuture<JsonRpcResult<U256>>;

    /// Returns highest epoch number.
    #[rpc(name = "cfx_epochNumber")]
    fn epoch_number(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<U256>;

    /// Returns balance of the given account.
    #[rpc(name = "cfx_getBalance")]
    fn balance(
        &self, addr: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> BoxFuture<JsonRpcResult<U256>>;

    /// Returns admin of the given contract
    #[rpc(name = "cfx_getAdmin")]
    fn admin(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<Option<RpcAddress>>>;

    /// Returns sponsor information of the given contract
    #[rpc(name = "cfx_getSponsorInfo")]
    fn sponsor_info(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<SponsorInfo>>;

    /// Returns balance of the given account.
    #[rpc(name = "cfx_getStakingBalance")]
    fn staking_balance(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<U256>>;

    /// Returns deposit list of the given account.
    #[rpc(name = "cfx_getDepositList")]
    fn deposit_list(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<Vec<DepositInfo>>>;

    /// Returns vote list of the given account.
    #[rpc(name = "cfx_getVoteList")]
    fn vote_list(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<Vec<VoteStakeInfo>>>;

    /// Returns balance of the given account.
    #[rpc(name = "cfx_getCollateralForStorage")]
    fn collateral_for_storage(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<U256>>;

    /// Returns the code at given address at given time (epoch number).
    #[rpc(name = "cfx_getCode")]
    fn code(
        &self, addr: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> BoxFuture<JsonRpcResult<Bytes>>;

    /// Returns storage entries from a given contract.
    #[rpc(name = "cfx_getStorageAt")]
    fn storage_at(
        &self, addr: RpcAddress, pos: U256,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> BoxFuture<JsonRpcResult<Option<H256>>>;

    #[rpc(name = "cfx_getStorageRoot")]
    fn storage_root(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<Option<StorageRoot>>>;

    /// Returns block with given hash.
    #[rpc(name = "cfx_getBlockByHash")]
    fn block_by_hash(
        &self, block_hash: H256, include_txs: bool,
    ) -> BoxFuture<JsonRpcResult<Option<Block>>>;

    /// Returns block with given hash and pivot chain assumption.
    #[rpc(name = "cfx_getBlockByHashWithPivotAssumption")]
    fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> BoxFuture<JsonRpcResult<Block>>;

    /// Returns block with given epoch number.
    #[rpc(name = "cfx_getBlockByEpochNumber")]
    fn block_by_epoch_number(
        &self, epoch_number: EpochNumber, include_txs: bool,
    ) -> BoxFuture<JsonRpcResult<Option<Block>>>;

    /// Returns block with given block number.
    #[rpc(name = "cfx_getBlockByBlockNumber")]
    fn block_by_block_number(
        &self, block_number: U64, include_txs: bool,
    ) -> BoxFuture<JsonRpcResult<Option<Block>>>;

    /// Returns best block hash.
    #[rpc(name = "cfx_getBestBlockHash")]
    fn best_block_hash(&self) -> JsonRpcResult<H256>;

    /// Returns the nonce should be filled in next sending transaction from
    /// given address at given time (epoch number).
    #[rpc(name = "cfx_getNextNonce")]
    fn next_nonce(
        &self, addr: RpcAddress, epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> BoxFuture<JsonRpcResult<U256>>;

    //        /// Returns the number of transactions in a block with given hash.
    //        #[rpc(name = "cfx_getBlockTransactionCountByHash")]
    //        fn block_transaction_count_by_hash(&self, H256) ->
    // BoxFuture<Option<U256>>;

    //        /// Returns the number of transactions in a block with given block
    // number.        #[rpc(name = "cfx_getBlockTransactionCountByNumber")]
    //        fn block_trasaction_count_by_number(&self, BlockNumber) ->
    // BoxFuture<Option<U256>>;

    /// Sends signed transaction, returning its hash.
    #[rpc(name = "cfx_sendRawTransaction")]
    fn send_raw_transaction(&self, raw_tx: Bytes) -> JsonRpcResult<H256>;

    //        /// @alias of `cfx_sendRawTransaction`.
    //        #[rpc(name = "cfx_submitTransaction")]
    //        fn submit_transaction(&self, Bytes) -> JsonRpcResult<H256>;

    /// Call contract, returning the output data.
    #[rpc(name = "cfx_call")]
    fn call(
        &self, tx: TransactionRequest,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> JsonRpcResult<Bytes>;

    /// Returns logs matching the filter provided.
    #[rpc(name = "cfx_getLogs")]
    fn get_logs(
        &self, filter: CfxRpcLogFilter,
    ) -> BoxFuture<JsonRpcResult<Vec<RpcLog>>>;

    /// Get transaction by its hash.
    #[rpc(name = "cfx_getTransactionByHash")]
    fn transaction_by_hash(
        &self, tx_hash: H256,
    ) -> BoxFuture<JsonRpcResult<Option<Transaction>>>;

    /// Get transaction pending info by account address
    #[rpc(name = "cfx_getAccountPendingInfo")]
    fn account_pending_info(
        &self, address: RpcAddress,
    ) -> BoxFuture<JsonRpcResult<Option<AccountPendingInfo>>>;

    /// Get transaction pending info by account address
    #[rpc(name = "cfx_getAccountPendingTransactions")]
    fn account_pending_transactions(
        &self, address: RpcAddress, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> BoxFuture<JsonRpcResult<AccountPendingTransactions>>;

    /// Return estimated gas and collateral usage.
    #[rpc(name = "cfx_estimateGasAndCollateral")]
    fn estimate_gas_and_collateral(
        &self, request: TransactionRequest, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<EstimateGasAndCollateralResponse>;

    #[rpc(name = "cfx_feeHistory")]
    fn fee_history(
        &self, block_count: HexU64, newest_block: EpochNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> BoxFuture<JsonRpcResult<CfxFeeHistory>>;

    /// Check if user balance is enough for the transaction.
    #[rpc(name = "cfx_checkBalanceAgainstTransaction")]
    fn check_balance_against_transaction(
        &self, account_addr: RpcAddress, contract_addr: RpcAddress,
        gas_limit: U256, gas_price: U256, storage_limit: U256,
        epoch: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<CheckBalanceAgainstTransactionResponse>>;

    #[rpc(name = "cfx_getBlocksByEpoch")]
    fn blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> JsonRpcResult<Vec<H256>>;

    #[rpc(name = "cfx_getSkippedBlocksByEpoch")]
    fn skipped_blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> JsonRpcResult<Vec<H256>>;

    #[rpc(name = "cfx_getTransactionReceipt")]
    fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> BoxFuture<JsonRpcResult<Option<RpcReceipt>>>;

    /// Return account related states of the given account
    #[rpc(name = "cfx_getAccount")]
    fn account(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<RpcAccount>>;

    /// Returns interest rate of the given epoch
    #[rpc(name = "cfx_getInterestRate")]
    fn interest_rate(
        &self, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<U256>>;

    /// Returns accumulate interest rate of the given epoch
    #[rpc(name = "cfx_getAccumulateInterestRate")]
    fn accumulate_interest_rate(
        &self, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<U256>>;

    /// Returns accumulate interest rate of the given epoch
    #[rpc(name = "cfx_getPoSEconomics")]
    fn pos_economics(
        &self, epoch_number: Option<EpochNumber>,
    ) -> BoxFuture<JsonRpcResult<PoSEconomics>>;

    #[rpc(name = "cfx_getConfirmationRiskByHash")]
    fn confirmation_risk_by_hash(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<U256>>;

    #[rpc(name = "cfx_getStatus")]
    fn get_status(&self) -> JsonRpcResult<RpcStatus>;

    /// Returns block reward information in an epoch
    #[rpc(name = "cfx_getBlockRewardInfo")]
    fn get_block_reward_info(
        &self, num: EpochNumber,
    ) -> JsonRpcResult<Vec<RpcRewardInfo>>;

    /// Return the client version as a string
    #[rpc(name = "cfx_clientVersion")]
    fn get_client_version(&self) -> JsonRpcResult<String>;

    /// Return information about total token supply.
    #[rpc(name = "cfx_getSupplyInfo")]
    fn get_supply_info(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<TokenSupplyInfo>;

    /// Return information about total token supply.
    #[rpc(name = "cfx_getCollateralInfo")]
    fn get_collateral_info(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<StorageCollateralInfo>;

    #[rpc(name = "cfx_getFeeBurnt")]
    fn get_fee_burnt(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<U256>;

    #[rpc(name = "cfx_getPoSRewardByEpoch")]
    fn get_pos_reward_by_epoch(
        &self, epoch: EpochNumber,
    ) -> JsonRpcResult<Option<PoSEpochReward>>;

    #[rpc(name = "cfx_getParamsFromVote")]
    fn get_vote_params(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<VoteParamsInfo>;

    //        /// Returns transaction at given block hash and index.
    //        #[rpc(name = "cfx_getTransactionByBlockHashAndIndex")]
    //        fn transaction_by_block_hash_and_index(&self, H256, Index) ->
    // BoxFuture<Option<Transaction>>;

    //        /// Returns transaction by given block number and index.
    //        #[rpc(name = "cfx_getTransactionByBlockNumberAndIndex")]
    //        fn transaction_by_block_number_and_index(&self, BlockNumber,
    // Index) -> BoxFuture<Option<Transaction>>;

    //        /// Returns uncles at given block and index.
    //        #[rpc(name = "cfx_getUnclesByBlockHashAndIndex")]
    //        fn uncles_by_block_hash_and_index(&self, H256, Index) ->
    // BoxFuture<Option<Block>>;

    //        /// Returns uncles at given block and index.
    //        #[rpc(name = "cfx_getUnclesByBlockNumberAndIndex")]
    //        fn uncles_by_block_number_and_index(&self, BlockNumber, Index) ->
    // BoxFuture<Option<Block>>;
}
