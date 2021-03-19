use crate::trace::trace::ActionType;
use cfx_types::H256;
use primitives::EpochNumber;

/// Log event Filter.
#[derive(Debug, PartialEq)]
pub struct TraceFilter {
    /// Search will be applied from this epoch number.
    pub from_epoch: EpochNumber,

    /// Till this epoch number.
    pub to_epoch: EpochNumber,

    /// Search will be applied in these blocks if given.
    /// This will override from/to_epoch fields.
    pub block_hashes: Option<Vec<H256>>,

    /// Search action.
    ///
    /// If None, match all.
    /// If specified, trace must match one of these action types.
    pub action_types: Option<Vec<ActionType>>,

    /// The offset trace number.
    pub after: Option<usize>,

    /// The number of traces to display in a batch.
    pub count: Option<usize>,
}
