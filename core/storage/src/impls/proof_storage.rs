// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct ProofStorage {
    proof: StateProof,
    root: StateRoot,
    maybe_intermediate_padding: Option<DeltaMptKeyPadding>,
}

impl ProofStorage {
    #![allow(unused)]
    pub fn new(
        proof: StateProof, root: StateRoot,
        maybe_intermediate_padding: Option<DeltaMptKeyPadding>,
    ) -> Self
    {
        Self {
            proof,
            root,
            maybe_intermediate_padding,
        }
    }
}

impl StateTrait for ProofStorage {
    fn commit(&mut self, epoch_id: EpochId) -> Result<StateRootWithAuxInfo> {
        bail!("Unexpected call on ProofStorage: commit({:?})", epoch_id);
    }

    fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        bail!("Unexpected call on ProofStorage: compute_state_root()");
    }

    fn delete(&mut self, access_key: StorageKey) -> Result<()> {
        bail!("Unexpected call on ProofStorage: delete({:?})", access_key);
    }

    fn delete_all<AM: access_mode::AccessMode>(
        &mut self, access_key_prefix: StorageKey,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        trace!(
            "ProofStorage::delete_all<{}>({:?})",
            AM::is_read_only(),
            access_key_prefix
        );

        if !AM::is_read_only() {
            bail!(
                "Unexpected call on ProofStorage: delete_all<Write>({:?})",
                access_key_prefix
            );
        }

        match self.proof.get_all_kv_in_subtree(
            access_key_prefix,
            &self.root,
            &self.maybe_intermediate_padding,
        ) {
            (false, _) => bail!(
                "Call failed on ProofStorage: delete_all({:?})",
                access_key_prefix
            ),
            (true, kvs) if kvs.is_empty() => Ok(None),
            (true, kvs) => Ok(Some(kvs)),
        }
    }

    fn delete_test_only(
        &mut self, access_key: StorageKey,
    ) -> Result<Option<Box<[u8]>>> {
        bail!(
            "Unexpected call on ProofStorage: delete_test_only({:?})",
            access_key
        );
    }

    fn get(&self, access_key: StorageKey) -> Result<Option<Box<[u8]>>> {
        trace!("ProofStorage::get({:?})", access_key);

        match self.proof.get_value(
            access_key,
            &self.root,
            &self.maybe_intermediate_padding,
        ) {
            (false, _) => {
                bail!("Call failed on ProofStorage: get({:?})", access_key)
            }
            (true, None) => Ok(None),
            (true, Some(v)) => Ok(Some(v.to_vec().into_boxed_slice())),
        }
    }

    fn get_state_root(&self) -> Result<StateRootWithAuxInfo> {
        bail!("Unexpected call on ProofStorage: get_state_root()");
    }

    fn set(&mut self, access_key: StorageKey, value: Box<[u8]>) -> Result<()> {
        bail!(
            "Unexpected call on ProofStorage: set({:?}, {:?})",
            access_key,
            value
        );
    }
}

use crate::{
    impls::{errors::*, merkle_patricia_trie::MptKeyValue},
    state::*,
    utils::access_mode,
    StateProof,
};
use cfx_internal_common::StateRootWithAuxInfo;
use primitives::{DeltaMptKeyPadding, EpochId, StateRoot, StorageKey};
