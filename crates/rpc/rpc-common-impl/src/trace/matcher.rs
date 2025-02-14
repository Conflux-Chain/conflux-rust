use cfx_parity_trace_types::{Action, ExecTrace};

/// Converts raw EVM execution steps into Parity-compatible trace entries,
/// pairing each action (call/create) with its corresponding result.
pub fn construct_parity_trace<'a>(
    tx_traces: &'a [ExecTrace],
) -> Result<Box<dyn 'a + Iterator<Item = TraceWithPosition<'a>>>, String> {
    let empty_traces = !tx_traces
        .iter()
        .any(|x| !matches!(x.action, Action::InternalTransferAction(_)));
    if empty_traces {
        return Ok(Box::new(std::iter::empty()));
    }

    let call_hierarchy = build_call_hierarchy(tx_traces)?;
    Ok(call_hierarchy.flatten_into_traces(vec![]))
}

/// Final trace output with execution position metadata
pub struct TraceWithPosition<'a> {
    pub action: &'a ExecTrace,
    pub result: &'a ExecTrace,
    pub child_count: usize,
    pub trace_path: Vec<usize>,
}

/// Represents an EVM execution frame with matched action-result pair
/// and nested child frames (sub-calls).
pub struct ResolvedTraceNode<'a> {
    action_trace: ActionTrace<'a>,
    result_trace: ResultTrace<'a>,
    child_nodes: Vec<ResolvedTraceNode<'a>>,
    total_child_count: usize,
}

impl<'a> ResolvedTraceNode<'a> {
    /// Creates a new node after validating action-result type consistency.
    ///
    /// # Arguments
    /// * `action` - Initiation of an EVM operation (Call/Create)
    /// * `result` - Completion of the operation (CallResult/CreateResult)
    /// * `children` - Child nodes from nested operations (contract creation or
    ///   message call)
    fn new(
        action: ActionTrace<'a>, result: ResultTrace<'a>,
        children: Vec<ResolvedTraceNode<'a>>,
    ) -> Result<Self, String> {
        // Validate action-result type pairing
        match (&action.0.action, &result.0.action) {
            (Action::Call(_), Action::CallResult(_))
            | (Action::Create(_), Action::CreateResult(_)) => {}
            _ => {
                return Err(format!(
                    "Type mismatch. Action: {:?}, Result: {:?}",
                    action.0.action, result.0.action
                ))
            }
        }

        // Calculate total children count (direct + indirect)
        let total_child_count = children.len()
            + children.iter().map(|x| x.total_child_count).sum::<usize>();

        Ok(Self {
            action_trace: action,
            result_trace: result,
            child_nodes: children,
            total_child_count,
        })
    }

    /// Converts hierarchical structure into flat iterator with positional
    /// metadata
    pub fn flatten_into_traces(
        self, trace_path: Vec<usize>,
    ) -> Box<dyn 'a + Iterator<Item = TraceWithPosition<'a>>> {
        // Current node's trace entry
        let root_entry = std::iter::once(TraceWithPosition {
            action: self.action_trace.0,
            result: self.result_trace.0,
            child_count: self.total_child_count,
            trace_path: trace_path.clone(),
        });

        // Recursively process child nodes
        let child_entries = self.child_nodes.into_iter().enumerate().flat_map(
            move |(idx, child)| {
                let mut child_path = trace_path.clone();
                child_path.push(idx);
                child.flatten_into_traces(child_path)
            },
        );

        Box::new(root_entry.chain(child_entries))
    }
}

/// Builds hierarchical call structure from raw traces.
/// Returns root node of the execution tree.
pub fn build_call_hierarchy<'a>(
    traces: &'a [ExecTrace],
) -> Result<ResolvedTraceNode<'a>, String> {
    // Stack tracks unclosed actions and their collected children
    let mut unclosed_actions: Vec<(ActionTrace, Vec<ResolvedTraceNode>)> =
        vec![];

    // Filter out internal transfer events (handled separately)
    let mut iter = traces
        .iter()
        .filter(|x| !matches!(x.action, Action::InternalTransferAction(_)));

    while let Some(trace) = iter.next() {
        match trace.action {
            // New operation - push to stack
            Action::Call(_) | Action::Create(_) => {
                let action = ActionTrace::try_from(trace).unwrap();
                unclosed_actions.push((action, vec![]));
            }

            // Operation completion - pop stack and build node
            Action::CallResult(_) | Action::CreateResult(_) => {
                let result = ResultTrace::try_from(trace).unwrap();

                let Some((action, children)) = unclosed_actions.pop() else {
                    return Err(format!(
                        "Orphaned result without matching action: {:?}",
                        trace
                    ));
                };

                let node = ResolvedTraceNode::new(action, result, children)?;

                // Attach to parent if exists, otherwise return as root
                if let Some((_, parent_children)) = unclosed_actions.last_mut()
                {
                    parent_children.push(node);
                } else {
                    return if let Some(trace) = iter.next() {
                        Err(format!(
                            "Trailing traces after root node closure: {:?}",
                            trace
                        ))
                    } else {
                        Ok(node)
                    };
                }
            }

            // Filtered out earlier
            Action::InternalTransferAction(_) => unreachable!(),
        }
    }
    // Loop should only exit when stack is empty
    Err("Incomplete trace: missing result for the root-level".into())
}

/// Helper types for type-safe action/result separation
struct ActionTrace<'a>(&'a ExecTrace);

/// Helper types for type-safe action/result separation
struct ResultTrace<'a>(&'a ExecTrace);

impl<'a> TryFrom<&'a ExecTrace> for ActionTrace<'a> {
    type Error = &'static str;

    fn try_from(trace: &'a ExecTrace) -> Result<Self, Self::Error> {
        match trace.action {
            Action::Call(_) | Action::Create(_) => Ok(Self(trace)),
            _ => Err("Not an action trace"),
        }
    }
}

impl<'a> TryFrom<&'a ExecTrace> for ResultTrace<'a> {
    type Error = &'static str;

    fn try_from(trace: &'a ExecTrace) -> Result<Self, Self::Error> {
        match trace.action {
            Action::CallResult(_) | Action::CreateResult(_) => Ok(Self(trace)),
            _ => Err("Not a result trace"),
        }
    }
}
