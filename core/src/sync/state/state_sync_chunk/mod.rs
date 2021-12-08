#[cfg(feature = "storage-dev")]
pub mod fake_snapshot_chunk_manager;
#[cfg(feature = "storage-dev")]
pub use fake_snapshot_chunk_manager as snapshot_chunk_manager;

#[cfg(not(feature = "storage-dev"))]
mod restore;
#[cfg(not(feature = "storage-dev"))]
pub mod snapshot_chunk_manager;
