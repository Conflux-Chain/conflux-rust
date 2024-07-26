/// An account entry in the checkpoint
#[derive(Debug, Clone)]
pub enum CheckpointEntry<T> {
    /// The account has not been read or modified from the database.
    Unchanged,
    /// The recorded state of the account at this checkpoint. It may be
    /// modified or unmodified.
    Recorded(T),
}
use CheckpointEntry::*;

impl<T> CheckpointEntry<T> {
    pub fn from_cache(value: Option<T>) -> Self {
        match value {
            Some(v) => Recorded(v),
            None => Unchanged,
        }
    }
}
