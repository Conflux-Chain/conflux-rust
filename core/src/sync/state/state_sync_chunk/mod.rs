#[cfg(feature = "storage_dev")]
pub mod fake_snapshot_chunk_manager;
#[cfg(feature = "storage_dev")]
pub use fake_snapshot_chunk_manager as snapshot_chunk_manager;

#[cfg(not(feature = "storage_dev"))]
mod restore;
#[cfg(not(feature = "storage_dev"))]
pub mod snapshot_chunk_manager;
