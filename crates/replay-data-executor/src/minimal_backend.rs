//! Minimal-MPT state backend for the replay executor.
//!
//! The replay executor runs the full execution layer (`cfx_executor::State`)
//! on top of `cfx_statedb::StateDb`, which in turn talks to a state-trie
//! backend through the `cfx_storage::state::StateTrait` object
//! (`StateDb::new(Box<dyn StorageStateTrait>)`). In the default build that
//! backend is the production `cfx-storage` MPT; under the
//! `backend-minimal-mpt` feature this module supplies an equivalent backend
//! built on the lightweight `cfx-minimal-mpt` crate.
//!
//! ## Why this is just one adapter
//!
//! `cfx-minimal-mpt`'s [`StateTrait`](cfx_minimal_mpt::StateTrait) mirrors the
//! `cfx-storage` `StateTrait` seam: `get` / `set` / `get_all_by_prefix` /
//! `delete_all_by_prefix` / `commit` over `StorageKeyWithSpace`. The only work
//! is (a) converting between the two crates' `StorageKeyWithSpace` / `H256`
//! types and (b) mapping `cfx-minimal-mpt`'s [`CommitRoot`] onto the
//! `StateRootWithAuxInfo` the executor compares.
//!
//! ## Latest-only, sequential
//!
//! `cfx-storage`'s interface assumes any historical state version can be
//! re-opened by `StateIndex`. `cfx-minimal-mpt` keeps only the latest state,
//! and the replay never needs more than that: epochs are executed strictly in
//! order, each on top of the immediately preceding committed state. So the
//! backend holds a single `cfx-minimal-mpt` `State` behind an `Arc<Mutex<_>>`
//! (the trait is `Sync + Send`), and every epoch wraps a fresh adapter around
//! that same shared state. `commit` advances the shared state in place, so the
//! next epoch's adapter continues from it — no history, no `StateIndex`.
//!
//! ## Root comparison
//!
//! The executor compares `StateRootWithAuxInfo.aux_info.state_root_hash`
//! (`consensus.rs`), which for the real backend is
//! `keccak(snapshot_root ‖ intermediate_delta_root ‖ delta_root)`.
//! `cfx-minimal-mpt`'s `CommitRoot.state_root_hash` is computed exactly the
//! same way, so the adapter forwards it verbatim.

use std::sync::{Arc, Mutex};

use cfx_internal_common::{StateRootAuxInfo, StateRootWithAuxInfo};
use cfx_minimal_mpt::{
    CommitRoot, Space as MmptSpace, State as MmptState,
    StateTrait as MmptStateTrait, StorageKey as MmptStorageKey,
    StorageKeyWithSpace as MmptKey,
};
use cfx_storage::{
    state::StateTrait as StorageStateTrait, Error as StorageError, MptKeyValue,
    Result as StorageResult,
};
use cfx_types::{Space, H256};
use primitives::{EpochId, StateRoot, StorageKey, StorageKeyWithSpace};

/// Snapshot period; must match `SNAPSHOT_EPOCHS_CAPACITY` / the value the real
/// backend rotates snapshots at, so the delta/intermediate/snapshot layering
/// (and therefore each epoch's three sub-roots) lines up.
pub const SNAPSHOT_EPOCH_COUNT: u32 = 2000;

// --- conversions -----------------------------------------------------------

fn storage_err(e: cfx_minimal_mpt::Error) -> StorageError {
    StorageError::Msg(format!("minimal-mpt backend: {e}"))
}

/// Bridge a `primitives` storage key to a `cfx-minimal-mpt` one.
///
/// The two crates' `StorageKey` enums are variant-for-variant mirrors, differing
/// only in ownership (`primitives` borrows `&[u8]`, `cfx-minimal-mpt` owns
/// `Vec<u8>`) and variant names. Every variant field carries the same raw bytes
/// on both sides — the canonical key-byte encoding is applied inside each crate's
/// own `to_key_bytes`, not stored in the fields — so the mapping is a direct,
/// infallible field copy. No round-trip through the byte encoding is needed.
fn to_mmpt_key(key: StorageKeyWithSpace) -> MmptKey {
    let mmpt_key = match key.key {
        StorageKey::AccountKey(address) => {
            MmptStorageKey::Account(address.to_vec())
        }
        StorageKey::StorageRootKey(address) => {
            MmptStorageKey::StorageRoot(address.to_vec())
        }
        StorageKey::StorageKey {
            address_bytes,
            storage_key,
        } => MmptStorageKey::Storage {
            address: address_bytes.to_vec(),
            storage_key: storage_key.to_vec(),
        },
        StorageKey::CodeRootKey(address) => {
            MmptStorageKey::CodeRoot(address.to_vec())
        }
        StorageKey::CodeKey {
            address_bytes,
            code_hash_bytes,
        } => MmptStorageKey::Code {
            address: address_bytes.to_vec(),
            code_hash: code_hash_bytes.to_vec(),
        },
        StorageKey::DepositListKey(address) => {
            MmptStorageKey::DepositList(address.to_vec())
        }
        StorageKey::VoteListKey(address) => {
            MmptStorageKey::VoteList(address.to_vec())
        }
        StorageKey::EmptyKey => MmptStorageKey::Empty,
        StorageKey::AddressPrefixKey(prefix) => {
            MmptStorageKey::AddressPrefix(prefix.to_vec())
        }
    };
    MmptKey {
        key: mmpt_key,
        space: match key.space {
            Space::Native => MmptSpace::Native,
            Space::Ethereum => MmptSpace::Ethereum,
        },
    }
}

fn to_cfx_h256(h: cfx_minimal_mpt::H256) -> H256 { H256(h.0) }

/// Map a `cfx-minimal-mpt` commit root onto the executor's
/// `StateRootWithAuxInfo`. Only `aux_info.state_root_hash` is compared by the
/// replay, so the aux info is filled with `genesis_state_root_aux_info` (which
/// sets exactly that field); the real three sub-roots are still carried in
/// `state_root` for completeness.
fn commit_root_to_aux(root: &CommitRoot) -> StateRootWithAuxInfo {
    let state_root = StateRoot {
        snapshot_root: to_cfx_h256(root.snapshot_root),
        intermediate_delta_root: to_cfx_h256(root.intermediate_delta_root),
        delta_root: to_cfx_h256(root.delta_root),
    };
    let state_root_hash = to_cfx_h256(root.state_root_hash);
    StateRootWithAuxInfo {
        state_root,
        aux_info: StateRootAuxInfo::genesis_state_root_aux_info(
            &state_root_hash,
        ),
    }
}

// --- shared backend handle -------------------------------------------------

/// Owns the single, latest `cfx-minimal-mpt` state shared across epochs.
#[derive(Clone)]
pub struct MinimalBackend {
    state: Arc<Mutex<MmptState>>,
}

impl MinimalBackend {
    /// Seed the backend with the genesis state.
    ///
    /// The genesis key/values (canonical key bytes → value, as dumped from the
    /// real backend) are written into the delta **without committing**, so the
    /// state stays at height 0 with genesis sitting in the delta — exactly
    /// where the real backend keeps it until the first snapshot boundary. The
    /// first real epoch then commits genesis + epoch-1 writes together, and
    /// snapshot rotation lands on the same epoch as the real backend.
    pub fn from_genesis_kvs(
        kvs: Vec<(Vec<u8>, Box<[u8]>)>,
    ) -> StorageResult<Self> {
        let mut state = MmptState::with_snapshot_epoch_count(SNAPSHOT_EPOCH_COUNT);
        for (raw_key, value) in kvs {
            let key = MmptKey::from_key_bytes(&raw_key)
                .map_err(|e| storage_err(e))?;
            state.set(key, value).map_err(|e| storage_err(e))?;
        }
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Wrap an already-constructed minimal-mpt `State` (e.g. one streamed from
    /// a checkpoint via `State::from_reader`, which avoids materializing the
    /// full byte-keyed snapshot `BTreeMap`).
    pub fn from_state(state: MmptState) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Run `f` while holding the state lock. Used for streaming checkpoint
    /// writes that need to iterate the snapshot trie without copying it.
    pub fn with_state<R>(&self, f: impl FnOnce(&MmptState) -> R) -> R {
        let state = self.state.lock().expect("minimal-mpt state poisoned");
        f(&state)
    }

    /// The committed height of the shared state (`== last pivot height`).
    /// Cheap (just reads the counter); used to know where a resumed run is.
    pub fn height(&self) -> u64 {
        self.state
            .lock()
            .expect("minimal-mpt state poisoned")
            .height()
    }

    /// A fresh per-epoch adapter sharing the backend's single state.
    pub fn open(&self) -> MinimalMptStorage {
        MinimalMptStorage {
            state: Arc::clone(&self.state),
            cached_root: None,
        }
    }
}

// --- the `StateDb` backend adapter -----------------------------------------

/// One epoch's view of the shared minimal-mpt state, implementing the trait
/// `StateDb` requires. A new instance is created per epoch (so `cached_root`
/// is naturally per-epoch); all instances mutate the same underlying state.
pub struct MinimalMptStorage {
    state: Arc<Mutex<MmptState>>,
    cached_root: Option<StateRootWithAuxInfo>,
}

impl StorageStateTrait for MinimalMptStorage {
    fn get(
        &self, access_key: StorageKeyWithSpace,
    ) -> StorageResult<Option<Box<[u8]>>> {
        let key = to_mmpt_key(access_key);
        self.state
            .lock()
            .expect("minimal-mpt state poisoned")
            .get(key)
            .map_err(|e| storage_err(e).into())
    }

    fn set(
        &mut self, access_key: StorageKeyWithSpace, value: Box<[u8]>,
    ) -> StorageResult<()> {
        let key = to_mmpt_key(access_key);
        self.state
            .lock()
            .expect("minimal-mpt state poisoned")
            .set(key, value)
            .map_err(|e| storage_err(e).into())
    }

    fn delete(&mut self, access_key: StorageKeyWithSpace) -> StorageResult<()> {
        // An empty value is a tombstone in minimal-mpt.
        self.set(access_key, Box::new([]))
    }

    fn delete_test_only(
        &mut self, access_key: StorageKeyWithSpace,
    ) -> StorageResult<Option<Box<[u8]>>> {
        let existing = self.get(access_key)?;
        if existing.is_some() {
            self.delete(access_key)?;
        }
        Ok(existing)
    }

    fn delete_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> StorageResult<Option<Vec<MptKeyValue>>> {
        let prefix = to_mmpt_key(access_key_prefix);
        self.state
            .lock()
            .expect("minimal-mpt state poisoned")
            .delete_all_by_prefix(prefix)
            .map_err(|e| storage_err(e).into())
    }

    fn read_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> StorageResult<Option<Vec<MptKeyValue>>> {
        let prefix = to_mmpt_key(access_key_prefix);
        self.state
            .lock()
            .expect("minimal-mpt state poisoned")
            .get_all_by_prefix(prefix)
            .map_err(|e| storage_err(e).into())
    }

    fn compute_state_root(&mut self) -> StorageResult<StateRootWithAuxInfo> {
        if let Some(ref root) = self.cached_root {
            return Ok(root.clone());
        }
        let commit_root = self
            .state
            .lock()
            .expect("minimal-mpt state poisoned")
            .commit()
            .map_err(|e| storage_err(e))?;
        let root = commit_root_to_aux(&commit_root);
        self.cached_root = Some(root.clone());
        Ok(root)
    }

    fn get_state_root(&self) -> StorageResult<StateRootWithAuxInfo> {
        self.cached_root
            .clone()
            .ok_or_else(|| StorageError::Msg("state root not computed".into()).into())
    }

    fn commit(
        &mut self, _epoch: EpochId,
    ) -> StorageResult<StateRootWithAuxInfo> {
        // The state was already advanced in place by `compute_state_root`; the
        // shared `Arc<Mutex<_>>` is the persistence, so there is nothing else
        // to flush. Return the same root.
        self.compute_state_root()
    }
}

#[cfg(test)]
mod smoke {
    use super::*;
    use cfx_minimal_mpt::{Space, StorageKey, MERKLE_NULL_NODE};

    fn account_key(byte: u8) -> MmptKey {
        MmptKey {
            key: StorageKey::Account(vec![byte; 20]),
            space: Space::Native,
        }
    }

    /// minimal-mpt links and round-trips set/get plus a non-empty commit root.
    #[test]
    fn minimal_mpt_backend_set_get_commit() {
        let mut state = MmptState::new();
        state.set(account_key(1), Box::from([9u8])).unwrap();
        assert_eq!(state.get(account_key(1)).unwrap().unwrap().as_ref(), &[9u8]);
        let root = state.commit().unwrap();
        assert_ne!(root.delta_root, MERKLE_NULL_NODE);
    }

    /// The adapter is object-safe as `Box<dyn StorageStateTrait>` (what
    /// `StateDb::new` takes) and round-trips a value through it.
    #[test]
    fn adapter_is_statedb_backend_object() {
        let backend = MinimalBackend::from_genesis_kvs(Vec::new()).unwrap();
        let mut boxed: Box<dyn StorageStateTrait> = Box::new(backend.open());

        // Build a `primitives` key (the type the real `StateDb` hands the
        // backend) and round-trip a value through the canonical-byte bridge.
        let addr = [7u8; 20];
        let prim_key =
            primitives::StorageKey::AccountKey(&addr).with_native_space();

        boxed.set(prim_key, Box::from([42u8])).unwrap();
        let got = boxed.get(prim_key).unwrap().unwrap();
        assert_eq!(got.as_ref(), &[42u8]);

        let root = boxed.compute_state_root().unwrap();
        // The compared field is populated.
        assert_ne!(root.aux_info.state_root_hash, H256::zero());
    }
}
