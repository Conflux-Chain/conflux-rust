use cfx_types::{Address, H256, U256, U64};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// BlockOverrides is a set of header fields to override.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockOverrides {
    /// Overrides the block number.
    ///
    /// For `eth_callMany` this will be the block number of the first simulated
    /// block. Each following block increments its block number by 1
    // Note: geth uses `number`, erigon uses `blockNumber`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "blockNumber"
    )]
    pub number: Option<U256>,
    /// Overrides the difficulty of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<U256>,
    /// Overrides the timestamp of the block.
    // Note: geth uses `time`, erigon uses `timestamp`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "timestamp"
    )]
    pub time: Option<U64>,
    /// Overrides the gas limit of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<U64>,
    /// Overrides the coinbase address of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<Address>,
    /// Overrides the prevrandao of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub random: Option<H256>,
    /// Overrides the basefee of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_fee: Option<U256>,
    /// A dictionary that maps blockNumber to a user-defined hash. It could be
    /// queried from the solidity opcode BLOCKHASH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BTreeMap<u64, H256>>,
}
