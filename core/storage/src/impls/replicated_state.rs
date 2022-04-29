use crate::{
    impls::errors::*,
    state::StateTrait,
    utils::access_mode::{self, AccessMode},
    MptKeyValue, NodeMerkleProof, StateProof, StorageStateTraitExt,
};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_types::Space;
use parking_lot::Mutex;
use primitives::{
    EpochId, NodeMerkleTriplet, StaticBool, StorageKey, StorageKeyWithSpace,
};
use std::{
    sync::{
        mpsc::{channel, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
};

pub struct ReplicatedState<Main> {
    state: Main,
    replication_handler: Option<ReplicationHandler>,
}

impl<Main: StateTrait> ReplicatedState<Main> {
    pub fn new<Replicate: StateTrait + Send + 'static>(
        main_state: Main, replicated_state: Replicate,
    ) -> ReplicatedState<Main> {
        let replication_handler = ReplicationHandler::new(replicated_state);
        Self {
            state: main_state,
            replication_handler: Some(replication_handler),
        }
    }

    pub fn new_single(main_state: Main) -> ReplicatedState<Main> {
        Self {
            state: main_state,
            replication_handler: None,
        }
    }

    pub fn into_main_state(self) -> Main { self.state }
}

struct ReplicationHandler {
    op_sender: Arc<Mutex<Sender<StateOperation>>>,
    thread_handle: JoinHandle<Result<()>>,
}

impl ReplicationHandler {
    fn new<Replicate: StateTrait + Send + 'static>(
        mut replicated_state: Replicate,
    ) -> ReplicationHandler {
        let (op_tx, op_rx) = channel();
        let thread_handle = thread::Builder::new()
            .name("state_replication".into())
            .spawn(move || {
                for op in op_rx {
                    let err = match op {
                        StateOperation::Set { access_key, value } => {
                            replicated_state
                                .set(access_key.as_storage_key(), value)
                                .err()
                        }
                        StateOperation::Delete { access_key } => {
                            replicated_state
                                .delete(access_key.as_storage_key())
                                .err()
                        }
                        StateOperation::DeleteAll { access_key_prefix } => {
                            replicated_state
                                .delete_all(access_key_prefix.as_storage_key())
                                .err()
                        }
                        StateOperation::ComputeStateRoot => {
                            replicated_state.compute_state_root().err()
                        }
                        StateOperation::Commit { epoch_id } => {
                            return replicated_state
                                .commit(epoch_id)
                                .map(|_| ());
                        }
                    };
                    if let Some(e) = err {
                        error!("StateReplication Error: err={:?}", e);
                        return Err(e);
                    }
                }
                Ok(())
            })
            .expect("spawn error");
        Self {
            op_sender: Arc::new(Mutex::new(op_tx)),
            thread_handle,
        }
    }

    fn send_op(&self, op: StateOperation) {
        if let Err(e) = self.op_sender.lock().send(op) {
            error!("send_op: err={:?}", e);
        }
    }

    pub fn join(self) -> Result<()> {
        self.thread_handle.join().expect("join error")
    }
}

enum StateOperation {
    Set {
        access_key: OwnedStorageKeyWithSpace,
        value: Box<[u8]>,
    },
    Delete {
        access_key: OwnedStorageKeyWithSpace,
    },
    DeleteAll {
        access_key_prefix: OwnedStorageKeyWithSpace,
    },
    ComputeStateRoot,
    Commit {
        epoch_id: EpochId,
    },
}

enum OwnedStorageKey {
    AccountKey(Vec<u8>),
    StorageRootKey(Vec<u8>),
    StorageKey {
        address_bytes: Vec<u8>,
        storage_key: Vec<u8>,
    },
    CodeRootKey(Vec<u8>),
    CodeKey {
        address_bytes: Vec<u8>,
        code_hash_bytes: Vec<u8>,
    },
    DepositListKey(Vec<u8>),
    VoteListKey(Vec<u8>),
}

impl OwnedStorageKey {
    fn as_storage_key(&self) -> StorageKey {
        match &self {
            OwnedStorageKey::AccountKey(k) => {
                StorageKey::AccountKey(k.as_slice())
            }
            OwnedStorageKey::StorageRootKey(k) => {
                StorageKey::StorageRootKey(k.as_slice())
            }
            OwnedStorageKey::StorageKey {
                address_bytes,
                storage_key,
            } => StorageKey::StorageKey {
                address_bytes: address_bytes.as_slice(),
                storage_key: &storage_key,
            },
            OwnedStorageKey::CodeRootKey(k) => {
                StorageKey::CodeRootKey(k.as_slice())
            }
            OwnedStorageKey::CodeKey {
                address_bytes,
                code_hash_bytes,
            } => StorageKey::CodeKey {
                address_bytes: &address_bytes,
                code_hash_bytes: &code_hash_bytes,
            },
            OwnedStorageKey::DepositListKey(k) => {
                StorageKey::DepositListKey(k.as_slice())
            }
            OwnedStorageKey::VoteListKey(k) => {
                StorageKey::VoteListKey(k.as_slice())
            }
        }
    }
}

struct OwnedStorageKeyWithSpace {
    pub key: OwnedStorageKey,
    pub space: Space,
}

impl OwnedStorageKeyWithSpace {
    fn as_storage_key(&self) -> StorageKeyWithSpace {
        StorageKeyWithSpace {
            key: self.key.as_storage_key(),
            space: self.space,
        }
    }
}

impl<'a> From<StorageKey<'a>> for OwnedStorageKey {
    fn from(ref_key: StorageKey<'a>) -> Self {
        match ref_key {
            StorageKey::AccountKey(k) => {
                OwnedStorageKey::AccountKey(k.to_vec())
            }
            StorageKey::StorageRootKey(k) => {
                OwnedStorageKey::StorageRootKey(k.to_vec())
            }
            StorageKey::StorageKey {
                address_bytes,
                storage_key,
            } => OwnedStorageKey::StorageKey {
                address_bytes: address_bytes.to_vec(),
                storage_key: storage_key.to_vec(),
            },
            StorageKey::CodeRootKey(k) => {
                OwnedStorageKey::CodeRootKey(k.to_vec())
            }
            StorageKey::CodeKey {
                address_bytes,
                code_hash_bytes,
            } => OwnedStorageKey::CodeKey {
                address_bytes: address_bytes.to_vec(),
                code_hash_bytes: code_hash_bytes.to_vec(),
            },
            StorageKey::DepositListKey(k) => {
                OwnedStorageKey::DepositListKey(k.to_vec())
            }
            StorageKey::VoteListKey(k) => {
                OwnedStorageKey::VoteListKey(k.to_vec())
            }
        }
    }
}

impl<'a> From<StorageKeyWithSpace<'a>> for OwnedStorageKeyWithSpace {
    fn from(ref_key: StorageKeyWithSpace<'a>) -> Self {
        Self {
            key: ref_key.key.into(),
            space: ref_key.space,
        }
    }
}

impl<Main: StateTrait> StateTrait for ReplicatedState<Main> {
    fn get(
        &self, access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        self.state.get(access_key)
    }

    fn set(
        &mut self, access_key: StorageKeyWithSpace, value: Box<[u8]>,
    ) -> Result<()> {
        self.replication_handler.as_ref().map(|h| {
            h.send_op(StateOperation::Set {
                access_key: access_key.into(),
                value: value.clone(),
            })
        });
        self.state.set(access_key, value)
    }

    fn delete(&mut self, access_key: StorageKeyWithSpace) -> Result<()> {
        self.replication_handler.as_ref().map(|h| {
            h.send_op(StateOperation::Delete {
                access_key: access_key.into(),
            })
        });
        self.state.delete(access_key)
    }

    fn delete_test_only(
        &mut self, _access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        todo!()
    }

    fn delete_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        self.replication_handler.as_ref().map(|h| {
            h.send_op(StateOperation::DeleteAll {
                access_key_prefix: access_key_prefix.into(),
            })
        });
        self.state.delete_all(access_key_prefix)
    }

    fn read_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        self.state.read_all(access_key_prefix)
    }

    fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        self.replication_handler
            .as_ref()
            .map(|h| h.send_op(StateOperation::ComputeStateRoot));
        self.state.compute_state_root()
    }

    fn get_state_root(&self) -> Result<StateRootWithAuxInfo> {
        self.state.get_state_root()
    }

    fn commit(&mut self, epoch_id: EpochId) -> Result<StateRootWithAuxInfo> {
        let r = self.state.commit(epoch_id);
        self.replication_handler
            .as_ref()
            .map(|h| h.send_op(StateOperation::Commit { epoch_id }));
        if let Some(h) = self.replication_handler.take() {
            h.thread_handle
                .join()
                .expect("ReplicationHandler thread join error")?;
        }
        r
    }
}

impl<Main: StorageStateTraitExt> StorageStateTraitExt
    for ReplicatedState<Main>
{
    fn get_with_proof(
        &self, access_key: StorageKeyWithSpace,
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        self.state.get_with_proof(access_key)
    }

    fn get_node_merkle_all_versions<WithProof: StaticBool>(
        &self, access_key: StorageKeyWithSpace,
    ) -> Result<(NodeMerkleTriplet, NodeMerkleProof)> {
        self.state
            .get_node_merkle_all_versions::<WithProof>(access_key)
    }
}
