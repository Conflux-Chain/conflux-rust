use crate::{
    executive::revert_reason_decode,
    trace::trace::{
        Action, Call, CallResult, Create, CreateResult, ExecTrace, Outcome,
    },
};
use cfx_types::Address;

/// An executive tracer only records errors during EVM unwind.
///
/// - Which errors will be retained?

#[derive(Default)]
pub struct ErrorUnwind {
    callstack: Vec<Address>,
    pub errors: Vec<(Address, String)>,
}

impl ErrorUnwind {
    pub fn from_traces(traces: Vec<ExecTrace>) -> Self {
        let mut errors = ErrorUnwind::default();
        for trace in traces.iter() {
            match &trace.action {
                Action::Call(call) => errors.accept_call(call),
                Action::Create(create) => errors.accept_create(create),
                Action::CallResult(result) => errors.accept_call_result(result),
                Action::CreateResult(result) => {
                    errors.accept_create_result(result)
                }
                Action::InternalTransferAction(_) => {}
            }
        }
        errors
    }

    fn accept_call(&mut self, call: &Call) {
        self.callstack.push(call.to);
        self.errors.clear();
    }

    fn accept_create(&mut self, _create: &Create) { self.errors.clear(); }

    fn accept_call_result(&mut self, result: &CallResult) {
        let address = self
            .callstack
            .pop()
            .expect("trace call and their results must be matched");

        match Self::error_message(&result.outcome, &result.return_data) {
            Some(message) => self.errors.push((address, message)),
            None => self.errors.clear(),
        }
    }

    fn accept_create_result(&mut self, result: &CreateResult) {
        let address = result.addr;

        match Self::error_message(&result.outcome, &result.return_data) {
            Some(message) => self.errors.push((address, message)),
            None => self.errors.clear(),
        }
    }

    fn error_message(
        outcome: &Outcome, return_data: &Vec<u8>,
    ) -> Option<String> {
        match outcome {
            Outcome::Success => None,
            Outcome::Reverted => Some(format!(
                "Vm reverted, {}",
                revert_reason_decode(return_data)
            )),
            Outcome::Fail => Some(
                String::from_utf8(return_data.clone())
                    .expect("Return data is encoded from valid utf-8 string"),
            ),
        }
    }
}
