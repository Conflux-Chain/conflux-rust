use super::{
    proof_type::{StateProof, StorageRootProof},
    state_manager::StateManager,
    state_trait::{StateTrait, StateTraitExt},
    state_trees::StateTrees,
};
use crate::{utils::access_mode::AccessMode, MptKeyValue};
use cfx_storage_primitives::{StateRootWithAuxInfo, StorageRoot};
use primitives::{EpochId, StaticBool, StorageKey};
use std::sync::Arc;

pub struct State;

impl StateTrait for State {
    fn get(&self, access_key: StorageKey) -> crate::Result<Option<Box<[u8]>>> {
        todo!()
    }

    fn set(
        &mut self, access_key: StorageKey, value: Box<[u8]>,
    ) -> crate::Result<()> {
        todo!()
    }

    fn delete(&mut self, access_key: StorageKey) -> crate::Result<()> {
        todo!()
    }

    fn delete_test_only(
        &mut self, access_key: StorageKey,
    ) -> crate::Result<Option<Box<[u8]>>> {
        unreachable!()
    }

    fn delete_all<AM: AccessMode>(
        &mut self, access_key_prefix: StorageKey,
    ) -> crate::Result<Option<Vec<MptKeyValue>>> {
        unimplemented!()
    }

    fn compute_state_root(&mut self) -> crate::Result<StateRootWithAuxInfo> {
        todo!()
    }

    fn get_state_root(&self) -> crate::Result<StateRootWithAuxInfo> { todo!() }

    fn commit(
        &mut self, epoch: EpochId,
    ) -> crate::Result<StateRootWithAuxInfo> {
        todo!()
    }
}

impl StateTraitExt for State {
    fn get_with_proof(
        &self, access_key: StorageKey,
    ) -> crate::Result<(Option<Box<[u8]>>, StateProof)> {
        todo!()
    }

    fn get_node_merkle_all_versions<WithProof: StaticBool>(
        &self, access_key: StorageKey,
    ) -> crate::Result<(StorageRoot, StorageRootProof)> {
        todo!()
    }
}
