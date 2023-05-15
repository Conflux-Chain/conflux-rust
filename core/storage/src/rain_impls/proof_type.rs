pub use cfx_storage_primitives::rain::{StateRoot, StorageRoot};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Default, Debug, RlpDecodable, RlpEncodable)]
pub struct StateProof;

#[derive(Clone, Default, Debug, RlpDecodable, RlpEncodable)]
pub struct StorageRootProof;

impl StorageRootProof {
    pub fn is_valid_with_prev_root(
        &self, key: &Vec<u8>, storage_root: &StorageRoot,
        state_root: StateRoot, maybe_prev_root: &Option<StateRoot>,
    ) -> bool
    {
        todo!()
    }
}

impl StateProof {
    pub fn is_valid_kv_with_prev_root(
        &self, key: &Vec<u8>, value: Option<&[u8]>, root: StateRoot,
        maybe_prev_root: &Option<StateRoot>,
    ) -> bool
    {
        todo!()
    }
}
