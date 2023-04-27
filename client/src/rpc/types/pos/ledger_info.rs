use crate::rpc::types::pos::{Decision, EpochState};
use cfx_types::{H256, U64};
use diem_types::{
    block_info::BlockInfo as PrimitiveBlockInfo,
    ledger_info::{
        LedgerInfo as PrimitiveLedgerInfo,
        LedgerInfoWithSignatures as PrimitiveLedgerInfoWithSignatures,
    },
    validator_config::ConsensusSignature,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerInfoWithSignatures {
    ledger_info: LedgerInfo,
    /// The validator is identified by its account address: in order to verify
    /// a signature one needs to retrieve the public key of the validator
    /// for the given epoch.
    signatures: BTreeMap<H256, ConsensusSignature>,
}

impl From<&PrimitiveLedgerInfoWithSignatures> for LedgerInfoWithSignatures {
    fn from(value: &PrimitiveLedgerInfoWithSignatures) -> Self {
        Self {
            ledger_info: value.ledger_info().into(),
            signatures: value
                .signatures()
                .iter()
                .map(|(k, v)| (H256::from(k.to_u8()), v.clone()))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerInfo {
    commit_info: BlockInfo,

    /// Hash of consensus specific data that is opaque to all parts of the
    /// system other than consensus.
    consensus_data_hash: H256,
}

impl From<&PrimitiveLedgerInfo> for LedgerInfo {
    fn from(value: &PrimitiveLedgerInfo) -> Self {
        Self {
            commit_info: value.commit_info().into(),
            consensus_data_hash: H256::from(
                value.consensus_data_hash().as_ref(),
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfo {
    /// Epoch number corresponds to the set of validators that are active for
    /// this block.
    epoch: U64,
    /// The consensus protocol is executed in rounds, which monotonically
    /// increase per epoch.
    round: U64,
    /// The identifier (hash) of the block.
    id: H256,
    /// The accumulator root hash after executing this block.
    executed_state_id: H256,
    /// The version of the latest transaction after executing this block.
    version: U64,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: U64,
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
    /// TODO(lpl): Remove Option?
    /// The last pivot block selection after executing this block.
    /// None means choosing TreeGraph genesis as the first pivot block.
    pivot: Option<Decision>,
}

impl From<&PrimitiveBlockInfo> for BlockInfo {
    fn from(value: &PrimitiveBlockInfo) -> Self {
        Self {
            epoch: value.epoch().into(),
            round: value.round().into(),
            id: H256::from(value.id().as_ref()),
            executed_state_id: H256::from(value.executed_state_id().as_ref()),
            version: value.version().into(),
            timestamp_usecs: value.timestamp_usecs().into(),
            next_epoch_state: value.next_epoch_state().map(|e| e.into()),
            pivot: value.pivot_decision().map(Into::into),
        }
    }
}
