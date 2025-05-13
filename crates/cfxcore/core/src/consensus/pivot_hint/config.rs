use crate::hash::H256;

/// Configuration for initializing PivotHint.
#[derive(Clone)]
pub struct PivotHintConfig {
    /// Path to the pivot hint file
    pub file_path: String,

    /// Expected keccak hash of the Page Digests Part
    pub checksum: H256,
}

impl PivotHintConfig {
    pub fn new(file_path: &str, checksum: H256) -> Self {
        Self {
            file_path: file_path.to_string(),
            checksum,
        }
    }
}
