use thiserror::Error;

/// Error type for block-related operations in the provider.
#[derive(Error, Debug)]
pub enum ProviderBlockError {
    #[error("Invalid params: expected a numbers with less than largest epoch number.")]
    EpochNumberTooLarge,
    #[error("{0}")]
    Common(String),
}

impl From<String> for ProviderBlockError {
    fn from(err: String) -> Self { ProviderBlockError::Common(err) }
}

impl From<&str> for ProviderBlockError {
    fn from(err: &str) -> Self { ProviderBlockError::Common(err.to_string()) }
}

impl Into<String> for ProviderBlockError {
    fn into(self) -> String { self.to_string() }
}
