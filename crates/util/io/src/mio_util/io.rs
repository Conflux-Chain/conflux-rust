// Re-export the io::Result / Error types for convenience
pub use std::io::{Error, ErrorKind, Read, Result, Write};

// TODO: Delete this
/// A helper trait to provide the map_non_block function on Results.
pub trait MapNonBlock<T> {
    /// Maps a `Result<T>` to a `Result<Option<T>>` by converting
    /// operation-would-block errors into `Ok(None)`.
    fn map_non_block(self) -> Result<Option<T>>;
}

impl<T> MapNonBlock<T> for Result<T> {
    fn map_non_block(self) -> Result<Option<T>> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(err) => {
                if let ErrorKind::WouldBlock = err.kind() {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }
}

/// Returns a std `WouldBlock` error without allocating
pub fn would_block() -> Error { ErrorKind::WouldBlock.into() }
