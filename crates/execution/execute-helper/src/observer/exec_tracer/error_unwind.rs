use super::{
    action_types::{Action, Call, CallResult, Create, CreateResult, Outcome},
    trace_types::ExecTrace,
    ExecTraceKey,
};
use cfx_executor::executive::Executed;
use cfx_types::Address;
use solidity_abi::string_revert_reason_decode;

/// An executive tracer only records errors during EVM unwind.
///
/// When the first error happens, `ErrorUnwind` tries to maintain a list for
/// error description and code address for triggering error. However, if the
/// tracer met a successful result or a sub-call/create, it will regard this
/// error as "caught" and clear the error list.
#[derive(Default)]
pub struct ErrorUnwind {
    callstack: Vec<Address>,
    pub errors: Vec<(Address, String)>,
}

impl ErrorUnwind {
    pub fn from_executed(executed: &Executed) -> Self {
        Self::from_traces(
            executed.ext_result.get::<ExecTraceKey>().unwrap_or(&vec![]),
        )
    }

    pub fn from_traces(traces: &[ExecTrace]) -> Self {
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

    // If contract A calls contract B, contract B returns with an exception (vm
    // error or reverted), but contract A makes another sub-call, we think
    // contract A catches this error and clear the error list.
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
            // If contract A calls contract B, contract B returns with an
            // exception (vm error or reverted), and contract A then
            // also returns with an exception, we think contract A is
            // propagating out the exception.
            Some(message) => self.errors.push((address, message)),
            // If contract A calls contract B, contract B returns with an
            // exception (vm error or reverted), but contract A
            // returns with success, we think contract A catches this error and
            // clear the error list.
            None => self.errors.clear(),
        }
    }

    fn accept_create_result(&mut self, result: &CreateResult) {
        let address = result.addr;

        match Self::error_message(&result.outcome, &result.return_data) {
            // If contract A calls contract B, contract B returns with an
            // exception (vm error or reverted), and contract A then
            // also returns with an exception, we think contract A is
            // propagating out the exception.
            Some(message) => self.errors.push((address, message)),
            // If contract A calls contract B, contract B returns with an
            // exception (vm error or reverted), but contract A
            // returns with success, we think contract A catches this error and
            // clear the error list.
            None => self.errors.clear(),
        }
    }

    fn error_message(
        outcome: &Outcome, return_data: &Vec<u8>,
    ) -> Option<String> {
        match outcome {
            Outcome::Success => None,
            Outcome::Reverted => Some(format!(
                "Vm reverted. {}",
                string_revert_reason_decode(return_data)
            )),
            Outcome::Fail => Some(
                String::from_utf8(return_data.clone())
                    .expect("Return data is encoded from valid utf-8 string"),
            ),
        }
    }
}
