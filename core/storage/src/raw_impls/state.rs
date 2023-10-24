use super::{
    proof_type::{StateProof, StorageRootProof},
    state_manager::StateManager,
    state_trait::{StateTrait, StateTraitExt},
    state_trees::StateTrees,
};
use crate::{utils::access_mode::AccessMode, MptKeyValue};
use cfx_storage_primitives::raw::{
    StateRoot, StateRootAuxInfo, StateRootWithAuxInfo, StorageRoot,
};
use keccak_hash::keccak;
use parking_lot::RwLock;
use primitives::{EpochId, StaticBool, StorageKey};
use std::sync::Arc;

use crate::{
    convert_key, STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2,
    STORAGE_GET_TIMER, STORAGE_GET_TIMER2, STORAGE_SET_TIMER,
    STORAGE_SET_TIMER2,
};
use cfx_types::H256;
use kvdb::{DBKey, DBOp, DBTransaction, DBValue, KeyValueDB};
use metrics::{MeterTimer, ScopeTimer};
use profile::metric_record;

pub struct State {
    pub(crate) read_only: bool,

    pub(crate) state: Arc<RwLock<Arc<dyn KeyValueDB>>>,
    pub(crate) epoch_id: H256,
}

impl StateTrait for State {
    fn get(&self, access_key: StorageKey) -> crate::Result<Option<Box<[u8]>>> {
        metric_record!(STORAGE_GET_TIMER, STORAGE_GET_TIMER2);

        Ok(self
            .state
            .read()
            .get(0, convert_key(access_key).as_ref())?
            .map(Into::into))
    }

    fn set(
        &mut self, access_key: StorageKey, value: Box<[u8]>,
    ) -> crate::Result<()> {
        assert!(!self.read_only);
        trace!("MPTStateOp: Set key {:?}, value {:?}", access_key, value);
        metric_record!(STORAGE_SET_TIMER, STORAGE_SET_TIMER2);

        self.state.write().write_buffered(DBTransaction {
            ops: vec![DBOp::Insert {
                col: 0,
                key: convert_key(access_key).0.into(),
                value: value.into_vec(),
            }],
        });
        Ok(())
    }

    fn delete(&mut self, access_key: StorageKey) -> crate::Result<()> {
        assert!(!self.read_only);
        trace!("MPTStateOp: Del key {:?}", access_key);
        metric_record!(STORAGE_SET_TIMER, STORAGE_SET_TIMER2);

        self.state.write().write_buffered(DBTransaction {
            ops: vec![DBOp::Delete {
                col: 0,
                key: convert_key(access_key).0.into(),
            }],
        });
        Ok(())
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
            "MPTState: No op for delete all. read only: {}, : key:{:?}",
            AM::is_read_only(),
            access_key_prefix
        );
        Ok(None)
    }

    fn compute_state_root(&mut self) -> crate::Result<StateRootWithAuxInfo> {
        metric_record!(STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2);
        assert!(!self.read_only);
        self.get_state_root()
    }

    fn get_state_root(&self) -> crate::Result<StateRootWithAuxInfo> {
        Ok(StateRootWithAuxInfo {
            state_root: StateRoot {
                epoch_id: self.epoch_id,
            },
            aux_info: StateRootAuxInfo {
                state_root_hash: self.epoch_id,
            },
        })
    }

    fn commit(
        &mut self, epoch: EpochId,
    ) -> crate::Result<StateRootWithAuxInfo> {
        metric_record!(STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2);

        self.epoch_id = epoch;
        self.state.write().flush();
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
