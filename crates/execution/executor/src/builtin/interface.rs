use cfx_bytes::BytesRef;
use cfx_types::U256;
use cfx_vm_types::Spec;

/// Execution error.
#[derive(Debug)]
pub struct Error(pub String);

impl From<&'static str> for Error {
    fn from(val: &'static str) -> Self { Error(val.into()) }
}

impl From<String> for Error {
    fn from(val: String) -> Self { Error(val) }
}

impl Into<cfx_vm_types::Error> for Error {
    fn into(self) -> cfx_vm_types::Error {
        cfx_vm_types::Error::BuiltIn(self.0)
    }
}

/// Native implementation of a built-in contract.
pub trait Precompile: Send + Sync {
    /// execute this built-in on the given input, writing to the given output.
    fn execute(&self, input: &[u8], output: &mut BytesRef)
        -> Result<(), Error>;
}

/// A gas pricing scheme for built-in contracts.
pub trait Pricer: Send + Sync {
    /// The gas cost of running this built-in for the given input data.
    fn cost(&self, input: &[u8]) -> U256;
}

pub trait PricePlan: Send + Sync {
    fn pricer(&self, spec: &Spec) -> &dyn Pricer;
}
