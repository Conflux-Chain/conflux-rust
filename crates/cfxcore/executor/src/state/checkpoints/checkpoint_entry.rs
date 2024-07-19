/// An account entry in the checkpoint
#[cfg_attr(test, derive(Clone))]
#[derive(Debug)]
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

    #[cfg(test)]
    pub fn into_cache(self) -> Option<T> {
        match self {
            Self::Recorded(storage_value) => Some(storage_value),
            Self::Unchanged => None,
        }
    }
}
