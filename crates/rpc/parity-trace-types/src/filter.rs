use super::{
    action_types::{Action, ActionType},
    trace_types::{ExecTrace, TransactionExecTraces},
};
use cfx_types::{Address, Space, H256};
use cfx_util_macros::bail;
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

    /// Return filtered Native actions with their orders kept.
    ///
    /// `from_address`, `to_address`, `action_types`, and `space` in `filter`
    /// are applied.
    pub fn filter_traces(
        &self, tx_traces: TransactionExecTraces,
    ) -> Result<Vec<ExecTrace>, String> {
        let mut traces = Vec::new();
        let mut stack = Vec::new();
        for trace in tx_traces.0 {
            match &trace.action {
                Action::Call(call) => {
                    if call.space == self.space
                        && self.from_address.matches(&call.from)
                        && self.to_address.matches(&call.to)
                        && self.action_types.matches(&ActionType::Call)
                    {
                        stack.push(true);
                        traces.push(trace);
                    } else {
                        // The corresponding result should be ignored.
                        stack.push(false);
                    }
                }
                Action::Create(create) => {
                    if create.space == self.space
                        && self.from_address.matches(&create.from)
                        // TODO(lpl): openethereum uses `to_address` to filter the contract address.
                        && self.action_types.matches(&ActionType::Create)
                    {
                        stack.push(true);
                        traces.push(trace);
                    } else {
                        // The corresponding result should be ignored.
                        stack.push(false);
                    }
                }
                Action::CallResult(_) | Action::CreateResult(_) => {
                    if stack
                        .pop()
                        .ok_or("result left unmatched!".to_string())?
                    {
                        // Since we know that traces should be paired correctly,
                        // we do not check if the type
                        // is correct here.
                        traces.push(trace);
                    }
                }
                Action::InternalTransferAction(_) => {
                    traces.push(trace);
                }
            }
        }
        if !stack.is_empty() {
            bail!("actions left unmatched!".to_string());
        }
        Ok(traces)
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
