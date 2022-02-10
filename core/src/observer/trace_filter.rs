use crate::observer::trace::ActionType;
use cfx_types::{Address, Space, H256};
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

    /// Search from_address.
    /// An empty vector matches all addresses.
    pub from_address: ListFilter<Address>,

    /// Search to_address.
    /// An empty vector matches all addresses.
    pub to_address: ListFilter<Address>,

    /// Search action.
    ///
    /// If None, match all.
    /// If specified, trace must match one of these action types.
    pub action_types: ListFilter<ActionType>,

    /// The offset trace number.
    pub after: Option<usize>,

    /// The number of traces to display in a batch.
    pub count: Option<usize>,

    /// The space to filter. This field is set according to RPC endpoints and
    /// cannot be set by RPC parameters.
    pub space: Space,
}

impl TraceFilter {
    pub fn space_filter(space: Space) -> TraceFilter {
        TraceFilter {
            from_epoch: EpochNumber::Earliest,
            to_epoch: EpochNumber::LatestState,
            block_hashes: None,
            from_address: Default::default(),
            to_address: Default::default(),
            action_types: Default::default(),
            after: None,
            count: None,
            space,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ListFilter<T: PartialEq> {
    list: Vec<T>,
}

impl<T: PartialEq> Default for ListFilter<T> {
    fn default() -> Self { ListFilter { list: Vec::new() } }
}

impl<T: PartialEq> From<Vec<T>> for ListFilter<T> {
    fn from(addresses: Vec<T>) -> Self { ListFilter { list: addresses } }
}

impl<T: PartialEq> ListFilter<T> {
    /// Returns true if address matches one of the searched addresses.
    pub fn matches(&self, address: &T) -> bool {
        self.matches_all() || self.list.contains(address)
    }

    /// Returns true if this address filter matches everything.
    pub fn matches_all(&self) -> bool { self.list.is_empty() }
}
