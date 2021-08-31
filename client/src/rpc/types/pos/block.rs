// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use serde_derive::Serialize;
use diem_types::block_info::PivotBlockDecision;
use cfx_types::{H256, U64};
use super::Transaction;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    ///
    pub hash: H256,
    ///
    pub block_number: U64,
    ///
    pub epoch: U64,
    ///
    pub round: U64,
    ///
    pub version: U64,
    ///
    pub miner: H256,
    ///
    pub parent_hash: H256,
    ///
    pub timestamp: U64,
    ///
    pub pivot_decision: PivotBlockDecision,
    ///
    pub transactions: BlockTransactions,
    ///
    pub signatures: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BlockTransactions {
    /// Only hashes
    Hashes(Vec<H256>),
    /// Full transactions
    Full(Vec<Transaction>),
}
