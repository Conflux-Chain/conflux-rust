// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// A block defines a list of transactions that it sees and the sequence of
/// the transactions (ledger). At the view of a block, after all
/// transactions being executed, the data associated with all addresses is
/// a State after the epoch defined by the block.
///
/// A writable state is copy-on-write reference to the base state in the
/// state manager. State is supposed to be owned by single user.
pub use super::impls::state::State;

// The trait is created to separate the implementation to another file, and the
// concrete struct is put into inner mod, because the implementation is
// anticipated to be too complex to present in the same file of the API.
// TODO(yz): check if this is the best way to organize code for this library.
pub trait StateTrait {
    // Verifiable proof related methods.
    fn get_with_proof(
        &self, access_key: StorageKey,
    ) -> Result<(Option<Box<[u8]>>, StateProof)>;

    // Actions.
    fn get(&self, access_key: StorageKey) -> Result<Option<Box<[u8]>>>;
    fn set(&mut self, access_key: StorageKey, value: Box<[u8]>) -> Result<()>;
    fn delete(&mut self, access_key: StorageKey) -> Result<Option<Box<[u8]>>>;
    // Delete everything prefixed by access_key and return deleted key value
    // pairs.
    fn delete_all(
        &mut self, access_key_prefix: StorageKey,
    ) -> Result<Option<Vec<(Vec<u8>, Box<[u8]>)>>>;

    // Finalize
    /// It's costly to compute state root however it's only necessary to compute
    /// state root once before committing.
    fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo>;
    fn get_state_root(&self) -> Result<Option<StateRootWithAuxInfo>>;
    fn commit(&mut self, epoch: EpochId) -> Result<()>;
    fn revert(&mut self);
}

use super::{
    impls::{errors::*, state_proof::StateProof},
    storage_key::*,
    StateRootWithAuxInfo,
};
use primitives::EpochId;
