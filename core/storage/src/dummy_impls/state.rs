use super::{
    proof_type::{StateProof, StorageRootProof},
    state_manager::StateManager,
    state_trait::{StateTrait, StateTraitExt},
    state_trees::StateTrees,
};
use crate::{utils::access_mode::AccessMode, MptKeyValue};
use amt_db::{crypto::export::ProjectiveCurve, serde::MyToBytes, AmtDb, Key};
use cfx_storage_primitives::dummy::{
    StateRoot, StateRootAuxInfo, StateRootWithAuxInfo, StorageRoot,
};
use keccak_hash::keccak;
use parking_lot::RwLock;
use primitives::{EpochId, StaticBool, StorageKey};
use std::sync::Arc;

pub struct State {
    pub(crate) read_only: bool,

    pub(crate) state: Arc<RwLock<AmtDb>>,
    pub(crate) root_with_aux: Option<StateRootWithAuxInfo>,
}

fn convert_key(access_key: StorageKey) -> Key {
    Key(keccak(access_key.to_key_bytes()).0.to_vec())
}

impl StateTrait for State {
    fn get(&self, access_key: StorageKey) -> crate::Result<Option<Box<[u8]>>> {
        Ok(self.state.read().get(&convert_key(access_key))?)
    }

    fn set(
        &mut self, access_key: StorageKey, value: Box<[u8]>,
    ) -> crate::Result<()> {
        assert!(!self.read_only);
        assert!(self.root_with_aux.is_none());
        debug!("AMTStateOp: Set key {:?}, value {:?}", access_key, value);
        self.state.write().set(&convert_key(access_key), value);
        Ok(())
    }

    fn delete(&mut self, access_key: StorageKey) -> crate::Result<()> {
        unimplemented!()
    }

    fn delete_test_only(
        &mut self, access_key: StorageKey,
    ) -> crate::Result<Option<Box<[u8]>>> {
        unreachable!()
    }

    fn delete_all<AM: AccessMode>(
        &mut self, access_key_prefix: StorageKey,
    ) -> crate::Result<Option<Vec<MptKeyValue>>> {
        warn!(
            "AMTState: No op for delete all. read only: {}, : key:{:?}",
            AM::is_read_only(),
            access_key_prefix
        );
        Ok(None)
    }

    fn compute_state_root(&mut self) -> crate::Result<StateRootWithAuxInfo> {
        assert!(!self.read_only);
        if self.root_with_aux.is_some() {
            warn!("AMTState: Do not commit me again");
            return Ok(self.root_with_aux.clone().unwrap());
        }

        let epoch = self.state.read().current_epoch()?;
        info!("AMTState: Compute state root for epoch {:?}", epoch);

        let (amt_root, static_root) = self.state.write().commit(0)?;
        let state_root = StateRoot {
            amt_root,
            static_root,
        };
        let state_root_hash = state_root.compute_state_root_hash();
        info!(
            "State root: hash {:?}, amt {:?}, static {:?}",
            state_root_hash,
            amt_root.into_affine(),
            static_root
        );

        self.root_with_aux = Some(StateRootWithAuxInfo {
            state_root,
            aux_info: StateRootAuxInfo { state_root_hash },
        });
        self.get_state_root()
    }

    fn get_state_root(&self) -> crate::Result<StateRootWithAuxInfo> {
        if let Some(root_with_aux) = &self.root_with_aux {
            Ok(root_with_aux.clone())
        } else {
            Err(crate::ErrorKind::DbIsUnclean.into())
        }
    }

    fn commit(
        &mut self, _epoch: EpochId,
    ) -> crate::Result<StateRootWithAuxInfo> {
        self.get_state_root()
    }
}

impl StateTraitExt for State {
    fn get_with_proof(
        &self, access_key: StorageKey,
    ) -> crate::Result<(Option<Box<[u8]>>, StateProof)> {
        unimplemented!()
    }

    fn get_node_merkle_all_versions<WithProof: StaticBool>(
        &self, access_key: StorageKey,
    ) -> crate::Result<(StorageRoot, StorageRootProof)> {
        unimplemented!()
    }
}
