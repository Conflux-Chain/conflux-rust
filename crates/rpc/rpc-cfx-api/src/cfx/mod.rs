// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_cfx_types::{
    pos::PoSEpochReward, Account as RpcAccount, Block, BlockHashOrEpochNumber,
    Bytes, CfxFeeHistory, CfxRpcLogFilter,
    CheckBalanceAgainstTransactionResponse, EpochNumber,
    EstimateGasAndCollateralResponse, Log as RpcLog, PoSEconomics,
    Receipt as RpcReceipt, RewardInfo as RpcRewardInfo, RpcAddress,
    SponsorInfo, Status as RpcStatus, StorageCollateralInfo, TokenSupplyInfo,
    Transaction, TransactionRequest, VoteParamsInfo,
};
use cfx_rpc_primitives::U64 as HexU64;
use cfx_types::{H256, U256, U64};
use jsonrpsee::{core::RpcResult as JsonRpcResult, proc_macros::rpc};
use primitives::{DepositInfo, StorageRoot, VoteStakeInfo};

mod cfx_filter;
mod debug;

pub use cfx_filter::*;
pub use debug::*;

/// Cfx rpc interface.
#[rpc(server, namespace = "cfx")]
pub trait CfxRpc {
    //        /// Returns protocol version encoded as a string (quotes are
    // necessary).        #[method(name = "protocolVersion")]
    //        fn protocol_version(&self) -> JsonRpcResult<String>;
    //
    /// Returns the number of hashes per second that the node is mining with.
    //        #[method(name = "hashrate")]
    //        fn hashrate(&self) -> JsonRpcResult<U256>;

    //        /// Returns block author.
    //        #[method(name = "coinbase")]
    //        fn author(&self) -> JsonRpcResult<H160>;

    //        /// Returns true if client is actively mining new blocks.
    //        #[method(name = "mining")]
    //        fn is_mining(&self) -> JsonRpcResult<bool>;

    /// Returns current gas price.
    #[method(name = "gasPrice")]
    async fn gas_price(&self) -> JsonRpcResult<U256>;

    /// Returns current max_priority_fee
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> JsonRpcResult<U256>;

    /// Returns highest epoch number.
    #[method(name = "epochNumber")]
    async fn epoch_number(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<U256>;

    /// Returns balance of the given account.
    #[method(name = "getBalance")]
    async fn balance(
        &self, addr: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> JsonRpcResult<U256>;

    /// Returns admin of the given contract
    #[method(name = "getAdmin")]
    async fn admin(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<Option<RpcAddress>>;

    /// Returns sponsor information of the given contract
    #[method(name = "getSponsorInfo")]
    async fn sponsor_info(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<SponsorInfo>;

    /// Returns balance of the given account.
    #[method(name = "getStakingBalance")]
    async fn staking_balance(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<U256>;

    /// Returns deposit list of the given account.
    #[method(name = "getDepositList")]
    async fn deposit_list(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<Vec<DepositInfo>>;

    /// Returns vote list of the given account.
    #[method(name = "getVoteList")]
    async fn vote_list(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<Vec<VoteStakeInfo>>;

    /// Returns balance of the given account.
    #[method(name = "getCollateralForStorage")]
    async fn collateral_for_storage(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<U256>;

    /// Returns the code at given address at given time (epoch number).
    #[method(name = "getCode")]
    async fn code(
        &self, addr: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> JsonRpcResult<Bytes>;

    /// Returns storage entries from a given contract.
    #[method(name = "getStorageAt")]
    async fn storage_at(
        &self, addr: RpcAddress, pos: U256,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> JsonRpcResult<Option<H256>>;

    #[method(name = "getStorageRoot")]
    async fn storage_root(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> JsonRpcResult<Option<StorageRoot>>;

    /// Returns block with given hash.
    #[method(name = "getBlockByHash")]
    async fn block_by_hash(
        &self, block_hash: H256, include_txs: bool,
    ) -> JsonRpcResult<Option<Block>>;

    /// Returns block with given hash and pivot chain assumption.
    #[method(name = "getBlockByHashWithPivotAssumption")]
    async fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> JsonRpcResult<Block>;

    /// Returns block with given epoch number.
    #[method(name = "getBlockByEpochNumber")]
    async fn block_by_epoch_number(
        &self, epoch_number: EpochNumber, include_txs: bool,
    ) -> JsonRpcResult<Option<Block>>;

    /// Returns block with given block number.
    #[method(name = "getBlockByBlockNumber")]
    async fn block_by_block_number(
        &self, block_number: U64, include_txs: bool,
    ) -> JsonRpcResult<Option<Block>>;

    /// Returns best block hash.
    #[method(name = "getBestBlockHash")]
    async fn best_block_hash(&self) -> JsonRpcResult<H256>;

    /// Returns the nonce should be filled in next sending transaction from
    /// given address at given time (epoch number).
    #[method(name = "getNextNonce")]
    async fn next_nonce(
        &self, addr: RpcAddress, epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> JsonRpcResult<U256>;

    //        /// Returns the number of transactions in a block with given hash.
    //        #[method(name = "getBlockTransactionCountByHash")]
    //        fn block_transaction_count_by_hash(&self, H256) ->
    // Option<U256>;

    //        /// Returns the number of transactions in a block with given block
    // number.        #[method(name = "getBlockTransactionCountByNumber")]
    //        fn block_trasaction_count_by_number(&self, BlockNumber) ->
    // Option<U256>;

    /// Sends signed transaction, returning its hash.
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, raw_tx: Bytes) -> JsonRpcResult<H256>;

    //        /// @alias of `sendRawTransaction`.
    //        #[method(name = "submitTransaction")]
    //        async fn submit_transaction(&self, Bytes) -> JsonRpcResult<H256>;

    /// Call contract, returning the output data.
    #[method(name = "call")]
    async fn call(
        &self, tx: TransactionRequest,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> JsonRpcResult<Bytes>;

    /// Returns logs matching the filter provided.
    #[method(name = "getLogs")]
    async fn get_logs(
        &self, filter: CfxRpcLogFilter,
    ) -> JsonRpcResult<Vec<RpcLog>>;

    /// Get transaction by its hash.
    #[method(name = "getTransactionByHash")]
    async fn transaction_by_hash(
        &self, tx_hash: H256,
    ) -> JsonRpcResult<Option<Transaction>>;

    /// Return estimated gas and collateral usage.
    #[method(name = "estimateGasAndCollateral")]
    async fn estimate_gas_and_collateral(
        &self, request: TransactionRequest, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<EstimateGasAndCollateralResponse>;

    #[method(name = "feeHistory")]
    async fn fee_history(
        &self, block_count: HexU64, newest_block: EpochNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> JsonRpcResult<CfxFeeHistory>;

    /// Check if user balance is enough for the transaction.
    #[method(name = "checkBalanceAgainstTransaction")]
    async fn check_balance_against_transaction(
        &self, account_addr: RpcAddress, contract_addr: RpcAddress,
        gas_limit: U256, gas_price: U256, storage_limit: U256,
        epoch: Option<EpochNumber>,
    ) -> JsonRpcResult<CheckBalanceAgainstTransactionResponse>;

    #[method(name = "getBlocksByEpoch")]
    async fn blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> JsonRpcResult<Vec<H256>>;

    #[method(name = "getSkippedBlocksByEpoch")]
    async fn skipped_blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> JsonRpcResult<Vec<H256>>;

    #[method(name = "getTransactionReceipt")]
    async fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> JsonRpcResult<Option<RpcReceipt>>;

    /// Return account related states of the given account
    #[method(name = "getAccount")]
    async fn account(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> JsonRpcResult<RpcAccount>;

    /// Returns interest rate of the given epoch
    #[method(name = "getInterestRate")]
    async fn interest_rate(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<U256>;

    /// Returns accumulate interest rate of the given epoch
    #[method(name = "getAccumulateInterestRate")]
    async fn accumulate_interest_rate(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<U256>;

    /// Returns accumulate interest rate of the given epoch
    #[method(name = "getPoSEconomics")]
    async fn pos_economics(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<PoSEconomics>;

    #[method(name = "getConfirmationRiskByHash")]
    async fn confirmation_risk_by_hash(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<U256>>;

    #[method(name = "getStatus")]
    async fn get_status(&self) -> JsonRpcResult<RpcStatus>;

    /// Returns block reward information in an epoch
    #[method(name = "getBlockRewardInfo")]
    async fn get_block_reward_info(
        &self, num: EpochNumber,
    ) -> JsonRpcResult<Vec<RpcRewardInfo>>;

    /// Return the client version as a string
    #[method(name = "clientVersion")]
    async fn get_client_version(&self) -> JsonRpcResult<String>;

    /// Return information about total token supply.
    #[method(name = "getSupplyInfo")]
    async fn get_supply_info(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<TokenSupplyInfo>;

    /// Return information about total token supply.
    #[method(name = "getCollateralInfo")]
    async fn get_collateral_info(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<StorageCollateralInfo>;

    #[method(name = "getFeeBurnt")]
    async fn get_fee_burnt(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<U256>;

    #[method(name = "getPoSRewardByEpoch")]
    async fn get_pos_reward_by_epoch(
        &self, epoch: EpochNumber,
    ) -> JsonRpcResult<Option<PoSEpochReward>>;

    #[method(name = "getParamsFromVote")]
    async fn get_vote_params(
        &self, epoch_number: Option<EpochNumber>,
    ) -> JsonRpcResult<VoteParamsInfo>;

    //        /// Returns transaction at given block hash and index.
    //        #[method(name = "getTransactionByBlockHashAndIndex")]
    //        fn transaction_by_block_hash_and_index(&self, H256, Index) ->
    // Option<Transaction>;

    //        /// Returns transaction by given block number and index.
    //        #[method(name = "getTransactionByBlockNumberAndIndex")]
    //        fn transaction_by_block_number_and_index(&self, BlockNumber,
    // Index) -> Option<Transaction>;

    //        /// Returns uncles at given block and index.
    //        #[method(name = "getUnclesByBlockHashAndIndex")]
    //        fn uncles_by_block_hash_and_index(&self, H256, Index) ->
    // Option<Block>;

    //        /// Returns uncles at given block and index.
    //        #[method(name = "getUnclesByBlockNumberAndIndex")]
    //        fn uncles_by_block_number_and_index(&self, BlockNumber, Index) ->
    // Option<Block>;
}
