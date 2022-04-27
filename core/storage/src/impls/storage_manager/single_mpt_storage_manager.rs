use super::super::errors::*;
use crate::{
    impls::{
        delta_mpt::node_ref_map::DeltaMptId, single_mpt_state::SingleMptState,
        state_manager::DeltaDbManager,
    },
    node_memory_manager::{
        DeltaMptsCacheAlgorithm, DeltaMptsNodeMemoryManager,
    },
    storage_db::DeltaDbManagerTrait,
    ArcDeltaDbWrapper, CowNodeRef, DeltaMpt, OpenableOnDemandOpenDeltaDbTrait,
};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use primitives::EpochId;
use std::{path::PathBuf, sync::Arc};

const DB_NAME: &str = "single_mpt";

pub struct SingleMptStorageManager {
    db_manager: Arc<DeltaDbManager>,
    node_memory_manager: Arc<DeltaMptsNodeMemoryManager>,
    mpt: Arc<DeltaMpt>,
}

impl SingleMptStorageManager {
    pub fn new_arc(db_path: PathBuf) -> Arc<Self> {
        let db_manager = Arc::new(
            DeltaDbManager::new(db_path).expect("DeltaDb initialize error"),
        );
        let node_memory_manager = Arc::new(DeltaMptsNodeMemoryManager::new(
            1_000_000,
            10_000_000,
            1_000_000,
            1_000_000,
            DeltaMptsCacheAlgorithm::new(10_000_000),
        ));
        let mpt = Arc::new(
            DeltaMpt::new_single_mpt(
                db_manager.clone(),
                node_memory_manager.clone(),
            )
            .expect("MPT initialization error"),
        );
        Arc::new(Self {
            db_manager,
            node_memory_manager,
            mpt,
        })
    }

    pub fn get_state_by_epoch(
        &self, epoch: EpochId,
    ) -> Result<Option<SingleMptState>> {
        let root = self.mpt.get_root_node_ref_by_epoch(&epoch)?;
        match root {
            Some(Some(root)) => {
                Ok(Some(SingleMptState::new(self.mpt.clone(), root)))
            }
            _ => Ok(None),
        }
    }

    pub fn get_state_for_genesis(&self) -> Result<SingleMptState> {
        Ok(SingleMptState::new_empty(self.mpt.clone()))
    }
}

impl OpenableOnDemandOpenDeltaDbTrait for DeltaDbManager {
    fn open(&self, mpt_id: DeltaMptId) -> Result<ArcDeltaDbWrapper> {
        if mpt_id == 0 {
            Ok(ArcDeltaDbWrapper {
                inner: Some(Arc::new(
                    self.get_delta_db(DB_NAME)?
                        .ok_or(Error::from(ErrorKind::DbNotExist))?,
                )),
                lru: None,
                mpt_id,
            })
        } else {
            Err(ErrorKind::DbNotExist.into())
        }
    }
}

impl MallocSizeOf for SingleMptStorageManager {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let mut size = 0;
        size += self.node_memory_manager.size_of(ops);
        size
    }
}
