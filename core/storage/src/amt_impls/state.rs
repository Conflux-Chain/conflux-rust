use super::{
    proof_type::{StateProof, StorageRootProof},
    state_manager::StateManager,
    state_trait::{StateTrait, StateTraitExt},
    state_trees::StateTrees,
};
use crate::{
    utils::access_mode::AccessMode, MptKeyValue, STORAGE_COMMIT_TIMER,
    STORAGE_COMMIT_TIMER2, STORAGE_GET_TIMER, STORAGE_GET_TIMER2,
    STORAGE_SET_TIMER, STORAGE_SET_TIMER2,
};
use cfx_storage_primitives::amt::{
    StateRoot, StateRootAuxInfo, StateRootWithAuxInfo, StorageRoot,
};
use keccak_hash::keccak;
use lvmt_db::{crypto::export::ProjectiveCurve, serde::MyToBytes, Key, LvmtDB};
use metrics::{Lock, MeterTimer, RwLockExtensions, ScopeTimer};
use parking_lot::RwLock;
use primitives::{EpochId, StaticBool, StorageKey};
use std::sync::Arc;

use profile::metric_record;

fn convert_key(key: StorageKey) -> Key {
    Key(crate::convert_key(key).0.to_vec())
}

lazy_static! {
    static ref GETLOCK: Lock = Lock::register("lock", "storage_get_lock");
    static ref SETLOCK: Lock = Lock::register("lock", "storage_set_lock");
    static ref COMMITLOCK: Lock = Lock::register("lock", "storage_commit_lock");
}
pub struct State {
    pub(crate) read_only: bool,

    pub(crate) state: Arc<RwLock<LvmtDB>>,
    pub(crate) root_with_aux: Option<StateRootWithAuxInfo>,
}

impl StateTrait for State {
    fn get(&self, access_key: StorageKey) -> crate::Result<Option<Box<[u8]>>> {
        metric_record!(STORAGE_GET_TIMER, STORAGE_GET_TIMER2);
        let state = self.state.read_with_metric(&GETLOCK);
        Ok(state.get(&convert_key(access_key))?)
    }

    fn set(
        &mut self, access_key: StorageKey, value: Box<[u8]>,
    ) -> crate::Result<()> {
        assert!(!self.read_only);
        assert!(self.root_with_aux.is_none());
        metric_record!(STORAGE_SET_TIMER, STORAGE_SET_TIMER2);
        trace!("AMTStateOp: Set key {:?}, value {:?}", access_key, value);
        let mut state = self.state.write_with_metric(&SETLOCK);

        state.set(&convert_key(access_key), value);

        Ok(())
    }

    fn delete(&mut self, access_key: StorageKey) -> crate::Result<()> {
        self.set(access_key, Default::default())
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
        metric_record!(STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2);

        assert!(!self.read_only);
        if self.root_with_aux.is_some() {
            warn!("AMTState: Do not commit me again");
            return Ok(self.root_with_aux.clone().unwrap());
        }

        let epoch = self.state.read().current_epoch()?;
        info!("AMTState: Compute state root for epoch {:?}", epoch);

        let mut state = self.state.write_with_metric(&COMMITLOCK);

        let (lvmt_root, static_root) = state.commit(0)?;
        let state_root = StateRoot {
            lvmt_root,
            static_root,
        };
        let state_root_hash = state_root.compute_state_root_hash();
        info!(
            "State root: hash {:?}, amt {:?}, static {:?}",
            state_root_hash,
            lvmt_root.into_affine(),
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
        metric_record!(STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2);
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
