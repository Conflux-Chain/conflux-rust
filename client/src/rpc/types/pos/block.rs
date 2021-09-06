// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::Transaction;
use cfx_types::{H256, U64};
use serde::{Serialize, Serializer};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    ///
    pub hash: H256,
    ///
    pub height: U64,
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
    pub pivot_decision: U64,
    ///
    pub transactions: BlockTransactions,
    ///
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    ///
    pub account: H256,
    ///
    pub signature: String,
}

#[derive(Debug)]
pub enum BlockTransactions {
    /// Only hashes
    Hashes(Vec<H256>),
    /// Full transactions
    Full(Vec<Transaction>),
}

impl Serialize for BlockTransactions {
    fn serialize<S: Serializer>(
        &self, serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match *self {
            BlockTransactions::Hashes(ref hashes) => {
                hashes.serialize(serializer)
            }
            BlockTransactions::Full(ref txs) => txs.serialize(serializer),
        }
    }
}
