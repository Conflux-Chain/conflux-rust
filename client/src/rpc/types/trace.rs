// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfxcore::trace::trace::{
    Action, BlockExecTraces, ExecTrace, TransactionExecTraces,
};
use serde::{ser::SerializeStruct, Serialize, Serializer};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedBlockTrace {
    pub transaction_traces: Vec<LocalizedTransactionTrace>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalizedTransactionTrace {
    pub traces: Vec<LocalizedTrace>,
}

#[derive(Debug)]
pub struct LocalizedTrace {
    pub action: Action,
}

impl Serialize for LocalizedTrace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut struc = serializer.serialize_struct("LocalizedTrace", 2)?;

        match self.action {
            Action::Call(ref call) => {
                struc.serialize_field("type", "call")?;
                struc.serialize_field("action", call)?;
            }
            Action::Create(ref create) => {
                struc.serialize_field("type", "create")?;
                struc.serialize_field("action", create)?;
            }
            Action::CallResult(ref call_result) => {
                struc.serialize_field("type", "call_result")?;
                struc.serialize_field("action", call_result)?;
            }
            Action::CreateResult(ref create_result) => {
                struc.serialize_field("type", "create_result")?;
                struc.serialize_field("action", create_result)?;
            }
            Action::InternalContractAction(ref internal_action) => {
                struc.serialize_field("type", "internal_contract_action")?;
                struc.serialize_field("action", internal_action)?;
            }
        }

        struc.end()
    }
}

impl From<ExecTrace> for LocalizedTrace {
    fn from(trace: ExecTrace) -> Self {
        LocalizedTrace {
            action: trace.action,
        }
    }
}

impl From<TransactionExecTraces> for LocalizedTransactionTrace {
    fn from(traces: TransactionExecTraces) -> Self {
        let traces: Vec<ExecTrace> = traces.into();
        LocalizedTransactionTrace {
            traces: traces.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<BlockExecTraces> for LocalizedBlockTrace {
    fn from(traces: BlockExecTraces) -> Self {
        let traces: Vec<TransactionExecTraces> = traces.into();
        LocalizedBlockTrace {
            transaction_traces: traces.into_iter().map(Into::into).collect(),
        }
    }
}
